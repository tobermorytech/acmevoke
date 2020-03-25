require "connection_pool"
require "redis"
require "securerandom"

class Acmevoke::Endpoint::NewNonce
	def self.field
		"newNonce"
	end

	def self.path
		"/newNonce"
	end

	def initialize(config)
		@redis = ConnectionPool.new { Redis.new }
	end

	def call(env)
		# Yes, I'm aware that RFC8555 says that HEAD getNonce "SHOULD" return a
		# 200, but RFC7231 says that a HEAD "SHOULD" send the same header fields
		# as a GET for the same resource, so I'm going with that one.
		status = case env["REQUEST_METHOD"]
		when "GET", "HEAD" then 204
		else
			raise Acmevoke::Error::HTTPMethodNotAllowed
		end

		nonce = SecureRandom.hex(64)

		@redis.with { |r| r.setex("acmevoke:nonce:#{nonce}", "1", 300) }

		[status, [["Replay-Nonce", nonce], ["Cache-Control", "no-store"]], [""]]
	end
end

Acmevoke::Endpoints << Acmevoke::Endpoint::NewNonce
