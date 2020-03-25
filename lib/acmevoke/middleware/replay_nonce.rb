require "connection_pool"
require "redis"
require "securerandom"

class Acmevoke::Middleware::ReplayNonce
	def initialize(app, config)
		@app, @config = app, config

		@redis = ConnectionPool.new { Redis.new(url: @config.redis_url.to_s) }
	end

	def call(env)
		@app.call(env).tap do |response|
			unless env["PATH_INFO"] == "/directory"
				nonce = SecureRandom.urlsafe_base64(16)
				@redis.with { |r| r.setex("acmevoke:nonce:#{nonce}", 300, "1") }
				response[1] << ["Replay-Nonce", nonce]
			end
		end
	end
end
