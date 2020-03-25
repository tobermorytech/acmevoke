class Acmevoke::Error < StandardError
	# Bad user, no biscuit
	class InvalidConfigError < self; end

	# AKA "a bug"
	class InternalError < self; end

	class HTTPError < self
		attr_reader :problem_type

		def initialize(message = default_message, problem_type: "about:blank")
			super(message)

			@problem_type = problem_type
		end

		def status
			#:nocov:
			raise InternalError, "#status not implemented on #{self.class}; this is a bug, please report it"
			#:nocov:
		end
	end

	class HTTPBadRequest < HTTPError
		def status; 400; end
		def default_message; "Bad Request"; end
	end

	class HTTPUnauthorized < HTTPError
		def status; 401; end
		def default_message; "Unauthorized"; end
	end

	class HTTPNotFound < HTTPError
		def status; 404; end
		def default_message; "Not Found"; end
	end

	class HTTPMethodNotAllowed < HTTPBadRequest
		def status; 405; end
		def default_message; "Method Not Allowed"; end
	end

	class HTTPPayloadTooLarge < HTTPBadRequest
		def status; 413; end
		def default_message; "Payload Too Large"; end
	end

	class HTTPUnsupportedMediaType < HTTPBadRequest
		def status; 415; end
		def default_message; "Content-Type header missing or invalid for this resource"; end
	end
end
