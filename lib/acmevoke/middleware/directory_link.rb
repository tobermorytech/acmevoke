require "connection_pool"
require "redis"
require "securerandom"

class Acmevoke::Middleware::DirectoryLink
	def initialize(app, config)
		@app, @config = app, config
	end

	def call(env)
		@app.call(env).tap do |response|
			response[1] << ["Link", "<#{@config.base_url.join("directory")}>;rel=\"index\""]
		end
	end
end
