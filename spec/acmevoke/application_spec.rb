require_relative "../spec_helper"

describe Acmevoke::Application do
	include Rack::Test::Methods

	uses_redis

	let(:env) do
		{
			"ACMEVOKE_ISSUER_CERTIFICATES_FILE"          => fixture_dir("issuer_certs").join("ca").to_s,
			"ACMEVOKE_REDIS_URL"                         => "redis://localhost:6379",
			"ACMEVOKE_BASE_URL"                          => "https://acmevoke.example.com",
			"ACMEVOKE_REVOCATION_NOTIFICATION_SENDER"    => "acmevoke@example.com",
			"ACMEVOKE_REVOCATION_NOTIFICATION_RECIPIENT" => "revocation@example.com",
			"ACMEVOKE_MAIL_DELIVERY_METHOD"              => "test",
		}
	end

	let(:config) { Acmevoke::Configuration.new(env) }
	let(:app)    { Acmevoke::Application.new(config) }

	context "when a non-existent path is requested" do
		before(:each) { get "/something/funny" }

		it_behaves_like "a problem report", status: 404, type: "about:blank"
	end

	context "when the directory is requested" do
		before(:each) { get "/directory" }
		let(:directory) { JSON.parse(last_response.body) }

		it_behaves_like "a successful JSON response"

		it "serves a JSON object" do
			expect(JSON.parse(last_response.body)).to be_a(Hash)
		end

		it "refers to a newNonce endpoint" do
			expect(directory).to have_key("newNonce")
		end

		it "refers to a revokeCert endpoint" do
			expect(directory).to have_key("revokeCert")
		end
	end

	context "when an unexpected error occurs" do
		let(:url) do
			get "/directory"
			JSON.parse(last_response.body)["newNonce"]
		end

		before(:each) do
			# This seems like a reasonable way to trigger an exception...
			allow(mock_redis).to receive(:setex).and_raise(Errno::EIO)
			allow($stderr).to receive(:puts)

			get url
		end

		it_behaves_like "a problem report", status: 500, type: "about:blank"

		it "logs the exception to stderr" do
			expect($stderr).to have_received(:puts).with(match(/Errno::EIO/))
		end
	end

	context "newNonce" do
		let(:url) do
			get "/directory"
			JSON.parse(last_response.body)["newNonce"]
		end

		describe "GET" do
			before(:each) { get url }

			it "returns a 204" do
				expect(last_response.status).to eq(204)
			end

			it "returns no body" do
				expect(last_response.body).to eq("")
			end

			it "returns a Replay-Nonce header" do
				expect(last_response["Replay-Nonce"]).to_not be_nil
			end

			it "sets the correct Cache-Control header" do
				expect(last_response["Cache-Control"]).to eq("no-store")
			end

			it "gives different nonces each time" do
				expect(get(url)["Replay-Nonce"]).to_not eq(get(url)["Replay-Nonce"])
			end

			it "stores the nonce for later" do
				expect(mock_redis).to have_received(:setex).with("acmevoke:nonce:#{last_response["Replay-Nonce"]}", 300, a_value)
			end

			it "includes a link back to the directory" do
				expect(last_response["Link"]).to eq('<https://acmevoke.example.com/directory>;rel="index"')
			end
		end

		describe "HEAD" do
			before(:each) { head url }

			it "returns a 204" do
				expect(last_response.status).to eq(204)
			end

			it "returns no body (obvs)" do
				expect(last_response.body).to eq("")
			end

			it "returns a Replay-Nonce header" do
				expect(last_response["Replay-Nonce"]).to_not be_nil
			end

			it "sets the correct Cache-Control header" do
				expect(last_response["Cache-Control"]).to eq("no-store")
			end

			it "gives different nonces each time" do
				expect(get(url)["Replay-Nonce"]).to_not eq(get(url)["Replay-Nonce"])
			end

			it "stores the nonce for later" do
				expect(mock_redis).to have_received(:setex).with("acmevoke:nonce:#{last_response["Replay-Nonce"]}", 300, a_value)
			end

			it "includes a link back to the directory" do
				expect(last_response["Link"]).to eq('<https://acmevoke.example.com/directory>;rel="index"')
			end
		end

		describe "PUT" do
			before(:each) { put url, "" }

			it_behaves_like "a problem report", status: 405, type: "about:blank"
		end
	end

	context "revokeCert" do
		before(:each) { Mail::TestMailer.deliveries.clear }

		let(:url) do
			get "/directory"
			JSON.parse(last_response.body)["revokeCert"]
		end

		let(:jws_alg) { "RS256" }
		let(:jws_nonce) { SecureRandom.hex(10) }
		let(:jws_url)   { url }
		let(:jws_signature_digest_class) { OpenSSL::Digest::SHA256 }
		let(:jws_signing_key) { OpenSSL::PKey::RSA.new(512) }
		let(:jws_header_jwk)  { JOSE::JWK.from_key(jws_signing_key.public_key).to_map.to_h }

		let(:cert_public_key) { jws_signing_key.public_key }
		let(:cert_not_before) { Time.now - 86400 }
		let(:cert_not_after)  { Time.now + 86400 }
		let(:ca_key)          { OpenSSL::PKey.read(fixture_dir("issuer_certs").join("ca.key").read) }
		let(:certificate) do
			OpenSSL::X509::Certificate.new.tap do |cert|
				cert.version = 2
				cert.serial  = 1

				cert.not_before = cert_not_before
				cert.not_after  = cert_not_after
				cert.subject    = OpenSSL::X509::Name.new([["CN", "acmevoke spec key"]])
				cert.issuer     = OpenSSL::X509::Name.new([["CN", "acmevoke spec CA"]])
				cert.public_key = cert_public_key

				cert.sign(ca_key, OpenSSL::Digest::SHA256.new)
			end
		end
		let(:encoded_certificate) { certificate.to_der.b64 }

		let(:protected_header) do
			{
				alg:   jws_alg,
				url:   jws_url,
				nonce: jws_nonce,
				jwk:   jws_header_jwk,
			}
		end

		let(:revocation_reason) { nil }

		let(:payload) do
			{
				certificate: encoded_certificate
			}.tap { |p| p[:reason] = revocation_reason if revocation_reason }
		end


		let(:encoded_protected) { protected_header.to_json.b64 }
		let(:encoded_payload) { payload.to_json.b64 }

		let(:jws_signature) { jws_signing_key.sign(jws_signature_digest_class.new, "#{encoded_protected}.#{encoded_payload}") }
		let(:encoded_signature) { jws_signature.b64 }

		let(:request_body) do
			{
				protected: encoded_protected,
				payload:   encoded_payload,
				signature: encoded_signature,
			}.to_json
		end

		let(:request_content_type) { "application/jose+json" }
		let(:extra_request_env)    { {} }

		let(:redis_del_return) { 1 }
		let(:redis_exists_return) { false }

		before(:each) do
			allow(mock_redis).to receive(:del).with("acmevoke:nonce:#{jws_nonce}").and_return(redis_del_return)
			allow(mock_redis).to receive(:exists).with(match(/^acmevoke:revoked_certificate:/)).and_return(redis_exists_return)
			allow(mock_redis).to receive(:set).with(/^acmevoke:revoked_certificate:/, a_value)

			post url, request_body, { "CONTENT_TYPE" => request_content_type }.merge(extra_request_env)
		end

		context "when all is well" do
			# Based on everything being setup correct, as it is by default in the
			# parent scope...
			it "returns a 200" do
				expect(last_response.status).to eq(200)
			end

			it "returns no body" do
				expect(last_response.body).to eq("")
				expect(last_response["Content-Length"]).to eq("0")
			end

			it "deactivates the provided nonce" do
				expect(mock_redis).to have_received(:del).with("acmevoke:nonce:#{jws_nonce}")
			end

			it "returns a *different* Replay-Nonce header" do
				expect(last_response["Replay-Nonce"]).to_not eq(jws_nonce)
			end

			it_behaves_like "a nonce issuer"

			it "includes a link back to the directory" do
				expect(last_response["Link"]).to eq('<https://acmevoke.example.com/directory>;rel="index"')
			end

			it "sends an e-mail" do
				expect(Mail::TestMailer.deliveries).to_not be_empty
			end

			it "remembers that we've revoked this certificate" do
				expect(mock_redis).to have_received(:set).with(match(/^acmevoke:revoked_certificate:/), a_value)
			end
		end

		context "when the revocation specifies key compromise" do
			let(:revocation_reason) { 1 }

			it "mentions that in the e-mail" do
				expect(Mail::TestMailer.deliveries.first.to_s).to match(/Revocation reason: key compromise/)
			end
		end

		context "when the revocation specifies no reason" do
			let(:revocation_reason) { 0 }

			it "succeeds" do
				expect(last_response).to be_ok
			end

			it "doesn't mention a revocation reason in the e-mail" do
				expect(Mail::TestMailer.deliveries.first.to_s).to_not match(/Revocation reason:/)
			end
		end

		context "when sent a GET" do
			before(:each) { get url }

			it_behaves_like "a problem report", status: 405, type: "about:blank"
		end

		context "with something that isn't JSON" do
			let(:request_body) { "foo=bar" }
			let(:request_content_type) { "application/x-www-form-urlencoded" }

			it_behaves_like "a problem report", status: 415, type: "urn:ietf:params:acme:error:malformed"
		end

		context "with invalid JSON" do
			let(:request_body) { "foo=bar" }

			it_behaves_like "a problem report", status: 400, type: "urn:ietf:params:acme:error:malformed"
		end

		context "when a weird Content-Length is provided" do
			let(:extra_request_env) { { "CONTENT_LENGTH" => "forty-two" } }

			it_behaves_like "a problem report", status: 400, type: "about:blank"
		end

		context "when a stupidly huge Content-Length is provided" do
			let(:extra_request_env) { { "CONTENT_LENGTH" => "1048577" } }

			it_behaves_like "a problem report", status: 413, type: "about:blank"
		end

		context "with valid JSON that isn't an object" do
			let(:request_body) { "[]" }

			it_behaves_like "a problem report", status: 400, type: "urn:ietf:params:acme:error:malformed"
		end

		context "with non-base64-encoded field values" do
			let(:encoded_protected) { "this is not valid base64" }

			it_behaves_like "a problem report", status: 400, type: "urn:ietf:params:acme:error:malformed"
		end

		context "with a missing jwk" do
			let(:protected_header) do
				{
					alg:   jws_alg,
					url:   jws_url,
					nonce: jws_nonce,
				}
			end

			it_behaves_like "a problem report", status: 400, type: "urn:ietf:params:acme:error:malformed"
		end

		context "with a non-object jwk" do
			let(:jws_header_jwk) { "s3kr1t" }

			it_behaves_like "a problem report", status: 400, type: "urn:ietf:params:acme:error:malformed"
		end

		context "with an unsupported jwk key type" do
			let(:jws_header_jwk) { { kty: "LOL" } }

			it_behaves_like "a problem report", status: 400, type: "urn:ietf:params:acme:error:badPublicKey"
		end

		context "with a supported jwk key type that's missing bits" do
			let(:jws_header_jwk) { { kty: "RSA", e: "AQAB" } }

			it_behaves_like "a problem report", status: 400, type: "urn:ietf:params:acme:error:malformed"
		end

		context "with both a jwk and a kid" do
			let(:protected_header) do
				{
					alg:   jws_alg,
					url:   jws_url,
					nonce: jws_nonce,
					jwk:   jws_header_jwk,
					kid:   {},
				}
			end

			it_behaves_like "a problem report", status: 400, type: "urn:ietf:params:acme:error:malformed"
		end

		context "with a JWS that lacks a signature" do
			let(:request_body) do
				{
					protected: encoded_protected,
					payload:   encoded_payload,
				}.to_json
			end

			it_behaves_like "a problem report", status: 400, type: "urn:ietf:params:acme:error:malformed"
		end

		context "with an unknown signature algorithm" do
			let(:jws_alg) { "LOLRUS" }

			it_behaves_like "a problem report", status: 400, type: "urn:ietf:params:acme:error:badSignatureAlgorithm"
		end

		context "with a signature that is just plain broken" do
			let(:encoded_signature) { "ACAB" }

			it_behaves_like "a problem report", status: 401, type: "urn:ietf:params:acme:error:unauthorized"
		end

		context "with a JWS signature from a different key to the jwk" do
			let(:jws_header_jwk)  { JOSE::JWK.from_key(OpenSSL::PKey::RSA.new(512).public_key).to_map.to_h }

			it_behaves_like "a problem report", status: 401, type: "urn:ietf:params:acme:error:unauthorized"
		end

		context "with a missing nonce" do
			let(:protected_header) do
				{
					alg:   jws_alg,
					url:   jws_url,
					jwk:   jws_header_jwk,
				}
			end

			it_behaves_like "a problem report", status: 400, type: "urn:ietf:params:acme:error:badNonce"
			it_behaves_like "a nonce issuer"
		end

		context "with an invalid nonce" do
			let(:redis_del_return) { 0 }

			it_behaves_like "a problem report", status: 400, type: "urn:ietf:params:acme:error:badNonce"
			it_behaves_like "a nonce issuer"
		end

		context "with a missing url" do
			let(:protected_header) do
				{
					alg:   jws_alg,
					nonce: jws_nonce,
					jwk:   jws_header_jwk,
				}
			end

			it_behaves_like "a problem report", status: 401, type: "urn:ietf:params:acme:error:unauthorized"
		end

		context "with the incorrect url" do
			let(:protected_header) do
				{
					alg:   jws_alg,
					nonce: jws_nonce,
					url:   "https://example.com/something/funny",
					jwk:   jws_header_jwk,
				}
			end

			it_behaves_like "a problem report", status: 401, type: "urn:ietf:params:acme:error:unauthorized"
		end

		context "with an unacceptable revocation reason" do
			let(:revocation_reason) { 42 }

			it_behaves_like "a problem report", status: 400, type: "urn:ietf:params:acme:error:badRevocationReason"
		end

		context "when the payload isn't JSON" do
			let(:encoded_payload) { "ohai!".b64 }

			it_behaves_like "a problem report", status: 400, type: "urn:ietf:params:acme:error:malformed"
		end

		context "when the payload isn't a JSON object" do
			let(:payload) { [] }

			it_behaves_like "a problem report", status: 400, type: "urn:ietf:params:acme:error:malformed"
		end

		context "when the payload doesn't have a certificate" do
			let(:payload) { {} }

			it_behaves_like "a problem report", status: 400, type: "urn:ietf:params:acme:error:malformed"
		end

		context "when the certificate isn't valid base64" do
			let(:encoded_certificate) { "this isn't base64 either" }

			it_behaves_like "a problem report", status: 400, type: "urn:ietf:params:acme:error:malformed"
		end

		context "when the certificate ASN.1 can't be parsed" do
			let(:encoded_certificate) { certificate.to_der[0..-3].b64 }

			it_behaves_like "a problem report", status: 400, type: "urn:ietf:params:acme:error:malformed"
		end

		context "when the certificate has already been marked for revocation" do
			let(:redis_exists_return) { true }

			it_behaves_like "a problem report", status: 400, type: "urn:ietf:params:acme:error:alreadyRevoked"
		end

		context "when the certificate key and JWS key don't match" do
			let(:cert_public_key) { OpenSSL::PKey::RSA.new(512).public_key }

			it_behaves_like "a problem report", status: 400, type: "urn:ietf:params:acme:error:badPublicKey"
		end

		context "when the certificate isn't signed by one of our issuers" do
			let(:ca_key) { OpenSSL::PKey::RSA.new(512) }

			it_behaves_like "a problem report", status: 404, type: "urn:ietf:params:acme:error:malformed"
		end
	end
end
