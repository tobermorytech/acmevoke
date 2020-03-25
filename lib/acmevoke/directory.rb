require "json"

class Acmevoke::Directory
	def initialize(endpoints, config)
		@response_body = Hash[endpoints.map { |ep| [ep.field, URI(config.base_url).join(ep.path)] }].to_json
	end

	def call(env)
		[200, [["Content-Type", "application/json"]], [@response_body]]
	end
end
