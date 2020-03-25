require "json"

class Acmevoke::Middleware::ExceptionHandler
	def initialize(app, config)
		@app, @config = app, config
	end

	def call(env)
		begin
			@app.call(env)
		rescue StandardError => ex
			$stderr.puts (["#{ex.message} (#{ex.class})"] + ex.backtrace).join("\n  ")

			doc = { status: 500, title: "Something has gone terribly wrong.", type: "about:blank" }

			[500, [["Content-Type", "application/problem+json"]], [doc.to_json]]
		end
	end
end
