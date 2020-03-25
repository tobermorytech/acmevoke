require "base64"
require "connection_pool"
require "jose"
require "mail"
require "redis"
require "securerandom"

class Acmevoke::Endpoint::RevokeCert
	def self.field
		"revokeCert"
	end

	def self.path
		"/revokeCert"
	end

	def initialize(config)
		@config = config

		@redis = ConnectionPool.new { Redis.new(url: @config.redis_url) }
		@issuer_store = OpenSSL::X509::Store.new.tap { |s| s.add_file(@config.issuer_certificates_file.to_s) }
	end

	def call(env)
		unless env["REQUEST_METHOD"] == "POST"
			raise Acmevoke::Error::HTTPMethodNotAllowed
		end

		unless env["CONTENT_TYPE"] == "application/jose+json"
			raise Acmevoke::Error::HTTPUnsupportedMediaType.new("Invalid Content-Type.  Must be application/jose+json", problem_type: "urn:ietf:params:acme:error:malformed")
		end

		unless env["CONTENT_LENGTH"]
			# Can't actually test this, because Rack::MockRequest *insists* on setting
			# CONTENT_LENGTH, so...
			#:nocov:
			raise Acmevoke::Error::HTTPLengthRequired.new("Content-Length header missing.")
			#:nocov:
		end

		unless env["CONTENT_LENGTH"] =~ /\A\d+\z/
			raise Acmevoke::Error::HTTPBadRequest.new("Invalid Content-Length header.")
		end

		content_length = env["CONTENT_LENGTH"].to_i

		# If someone can manage to generate a valid revocation request larger
		# than 1MB, I'll buy them a beer
		if content_length > 1_048_576
			raise Acmevoke::Error::HTTPPayloadTooLarge.new("Too much winning.")
		end

		begin
			jws_bits = JSON.parse(env["rack.input"].read(content_length))

			unless jws_bits.is_a?(Hash) && jws_bits.values.all? { |p| p =~ /\A[A-Za-z0-9_-]+\z/ }
				raise Acmevoke::Error::HTTPBadRequest.new("Failed to parse JWS", problem_type: "urn:ietf:params:acme:error:malformed")
			end

			map = JOSE::SignedMap[jws_bits]
			jwk = map.compact.peek_protected["jwk"]

			unless jwk.is_a?(Hash)
				raise Acmevoke::Error::HTTPBadRequest.new("Missing or malformed key", problem_type: "urn:ietf:params:acme:error:malformed")
			end

			if map.compact.peek_protected["kid"]
				raise Acmevoke::Error::HTTPBadRequest.new("Must not include both jwk and kid", problem_type: "urn:ietf:params:acme:error:malformed")
			end

			begin
				jwk = JOSE::JWK.from_map(jwk)
			rescue ArgumentError => ex
				if ex.message =~ /unknown 'kty'/
					raise Acmevoke::Error::HTTPBadRequest.new("Unsupported key type", problem_type: "urn:ietf:params:acme:error:badPublicKey")
				else
					raise Acmevoke::Error::HTTPBadRequest.new("Malformed key", problem_type: "urn:ietf:params:acme:error:malformed")
				end
			end

			begin
				sig_ok, payload, jws = JOSE::JWS.verify(jwk, map)
			rescue ArgumentError => ex
				if ex.message =~ /unknown 'alg'/
					raise Acmevoke::Error::HTTPBadRequest.new("Unsupported JWS signature algorithm", problem_type: "urn:ietf:params:acme:error:badSignatureAlgorithm")
				else
					raise Acmevoke::Error::HTTPBadRequest.new("JWS signature validation error", problem_type: "urn:ietf:params:acme:error:malformed")
				end
			end

			unless sig_ok
				raise Acmevoke::Error::HTTPUnauthorized.new("JWS signature validation failed", problem_type: "urn:ietf:params:acme:error:unauthorized")
			end

			nonce = map.compact.peek_protected["nonce"]
			if nonce.nil?
				raise Acmevoke::Error::HTTPBadRequest.new("No nonce specified", problem_type: "urn:ietf:params:acme:error:badNonce")
			end

			@redis.with do |r|
				unless r.del("acmevoke:nonce:#{nonce}") == 1
					raise Acmevoke::Error::HTTPBadRequest.new("Invalid nonce", problem_type: "urn:ietf:params:acme:error:badNonce")
				end
			end

			url = map.compact.peek_protected["url"]
			if url.nil?
				raise Acmevoke::Error::HTTPUnauthorized.new("No url parameter", problem_type: "urn:ietf:params:acme:error:unauthorized")
			end

			unless url == @config.base_url.join("revokeCert").to_s
				raise Acmevoke::Error::HTTPUnauthorized.new("Incorrect url parameter -- expected #{@config.base_url.join("revokeCert").to_s}, got #{url}", problem_type: "urn:ietf:params:acme:error:unauthorized")
			end

			payload = JSON.parse(payload)
		rescue JSON::ParserError
			raise Acmevoke::Error::HTTPBadRequest.new("Failed to parse JWS", problem_type: "urn:ietf:params:acme:error:malformed")
		end

		unless payload.is_a?(Hash)
			raise Acmevoke::Error::HTTPBadRequest.new("Malformed payload -- must be an object", problem_type: "urn:ietf:params:acme:error:malformed")
		end

		unless payload["certificate"]
			raise Acmevoke::Error::HTTPBadRequest.new("No certificate specified", problem_type: "urn:ietf:params:acme:error:malformed")
		end

		unless payload["certificate"] =~ /\A[A-Za-z0-9_-]+\z/
			raise Acmevoke::Error::HTTPBadRequest.new("Certificate incorrectly encoded", problem_type: "urn:ietf:params:acme:error:malformed")
		end

		begin
			cert = OpenSSL::X509::Certificate.new(Base64.urlsafe_decode64(payload["certificate"]))
		rescue OpenSSL::X509::CertificateError
			raise Acmevoke::Error::HTTPBadRequest.new("Certificate parsing failed", problem_type: "urn:ietf:params:acme:error:malformed")
		end

		@redis.with do |r|
			if r.exists("acmevoke:revoked_certificate:#{b64(Digest::SHA256.digest(cert.to_der))}")
				raise Acmevoke::Error::HTTPBadRequest.new("Certificate already revoked", problem_type: "urn:ietf:params:acme:error:alreadyRevoked")
			end
		end

		unless JOSE::JWK.from_key(cert.public_key) == jwk
			raise Acmevoke::Error::HTTPBadRequest.new("Revocation request not signed by the certificate public key", problem_type: "urn:ietf:params:acme:error:badPublicKey")
		end

		unless @issuer_store.verify(cert)
			raise Acmevoke::Error::HTTPNotFound.new("Certificate not found", problem_type: "urn:ietf:params:acme:error:malformed")
		end

		if payload["reason"] && ![0, 1].include?(payload["reason"])
			raise Acmevoke::Error::HTTPBadRequest.new("Invalid revocation reason #{payload["reason"].inspect} -- we only accept '1' (keyCompromised)", problem_type: "urn:ietf:params:acme:error:badRevocationReason")
		end

		# Holy shit we made it!  Revocation time!
		mail = Mail.new
		mail.from    @config.notification_sender
		mail.to      @config.notification_recipient
		mail.subject "ACMEvoke validated revocation notification"

		body = <<~EOF
		  The attached certificate has been submitted for revocation.
		  The submission was signed by the private key of the certificate,
		  and as such control of the private key has been verified.
		EOF

		if payload["reason"] == 1
			body << "\n\nRevocation reason: key compromise"
		end

		mail.body body
		mail.add_file filename: "cert.pem", content: cert.to_pem

		mail.delivery_method @config.mail_delivery_method, @config.mail_delivery_config
		mail.deliver

		@redis.with do |r|
			r.set("acmevoke:revoked_certificate:#{b64(Digest::SHA256.digest(cert.to_der))}", Time.now.to_s)
		end

		[200, [["Content-Length", "0"]], [""]]
	end

	private

	def b64(s)
		Base64.urlsafe_encode64(s).sub(/=*$/, "")
	end
end

Acmevoke::Endpoints << Acmevoke::Endpoint::RevokeCert
