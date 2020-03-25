require "json"

class Acmevoke::Middleware::HttpErrorRenderer
	def initialize(app, config)
		@app, @config = app, config
	end

	def call(env)
		begin
			@app.call(env)
		rescue Acmevoke::Error::HTTPError => err
			doc = { status: err.status, title: err.message, type: err.problem_type }

			# Whatever you were going to do before, it's cancelled
			[
				err.status,
				[["Content-Type", "application/problem+json"]],
				[doc.to_json]
			]
		end
	end
end
