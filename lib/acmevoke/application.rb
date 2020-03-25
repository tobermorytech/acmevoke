require "rack/builder"

class Acmevoke::Application
	def self.new(config)
		Rack::Builder.app do
			use Acmevoke::Middleware::ExceptionHandler, config
			use Acmevoke::Middleware::ReplayNonce, config
			use Acmevoke::Middleware::HttpErrorRenderer, config

			map("/directory") do
				run Acmevoke::Directory.new(Acmevoke::Endpoints, config)
			end

			Acmevoke::Endpoints.each do |ep|
				use Acmevoke::Middleware::DirectoryLink, config

				map(ep.path) { run ep.new(config) }
			end

			map("/") do
				run ->(env) {
					[
						404,
						[["Content-Type", "application/problem+json"]],
						['{"type":"about:blank","title":"Not Found","status":404}']
					]
				}
			end
		end
	end
end
