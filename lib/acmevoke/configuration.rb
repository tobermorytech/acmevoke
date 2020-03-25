require "email_address_validator"
require "openssl"
require "pathname"

class Acmevoke::Configuration
	attr_reader :base_url,
	            :redis_url,
	            :issuer_certificates_file,
	            :notification_sender,
	            :notification_recipient,
	            :mail_delivery_method,
	            :mail_delivery_config

	def initialize(env)
		@base_url                 = fetch_url("ACMEVOKE_BASE_URL", env)
		@redis_url                = fetch_url("ACMEVOKE_REDIS_URL", env)
		@issuer_certificates_file = fetch_file("ACMEVOKE_ISSUER_CERTIFICATES_FILE", env)
		@notification_sender      = fetch_email_address("ACMEVOKE_REVOCATION_NOTIFICATION_SENDER", env)
		@notification_recipient   = fetch_email_address("ACMEVOKE_REVOCATION_NOTIFICATION_RECIPIENT", env)
		@mail_delivery_method     = fetch_mail_delivery_method("ACMEVOKE_MAIL_DELIVERY_METHOD", env)
		@mail_delivery_config     = fetch_mail_delivery_config(env)
	end

	private

	def fetch_var(var, env)
		unless env.has_key?(var)
			raise Acmevoke::Error::InvalidConfigError,
			      "Required environment variable #{var} not found"
		end

		env[var]
	end

	def fetch_url(var, env)
		begin
			URI(fetch_var(var, env))
		rescue URI::InvalidURIError
			raise Acmevoke::Error::InvalidConfigError,
			      "Value for #{var.inspect} specified in #{var} is not a valid URL"
		end
	end

	def fetch_file(var, env)
		Pathname.new(fetch_var(var, env).tap do |file|
			unless File.exists?(file)
				raise Acmevoke::Error::InvalidConfigError,
				      "File #{file.inspect} specified in #{var} does not exist"
			end

			unless File.readable?(file)
				raise Acmevoke::Error::InvalidConfigError,
				      "File #{file.inspect} specified in #{var} is not readable"
			end
		end)
	end

	def fetch_email_address(var, env)
		fetch_var(var, env).tap do |addr|
			unless EmailAddressValidator.validate_addr(addr, true)
				raise Acmevoke::Error::InvalidConfigError,
				      "E-mail address #{addr.inspect} specified in #{var} does not appear to be a valid e-mail address"
			end
		end
	end

	def fetch_mail_delivery_method(var, env)
		method = fetch_var(var, env)

		if %w{smtp sendmail file stderr test}.include?(method)
			method.to_sym
		else
			raise Acmevoke::Error::InvalidConfigError,
			      "Mail delivery method #{method.inspect} specified in #{var} is not a valid mail delivery method"
		end
	end

	def fetch_mail_delivery_config(env)
		case @mail_delivery_method
		when :smtp
			fetch_smtp_delivery_config(env)
		when :sendmail
			fetch_sendmail_delivery_config(env)
		when :file
			fetch_file_delivery_config(env)
		when :stderr, :test
			# These methods have no config
			{}
		else
			#:nocov:
			# Just in case
			raise Acmevoke::Error::InternalError,
			      "Unrecognised @mail_delivery_method #{@mail_delivery_method.inspect}; this is a bug, please report it"
			#:nocov:
		end
	end

	def fetch_smtp_delivery_config(env)
		{}.tap do |cfg|
			cfg[:address] = env.fetch("ACMEVOKE_MAIL_DELIVERY_CONFIG_ADDRESS", "localhost")
			# No validation for address; if you want to be a goose, go for your life

			cfg[:port]    = env.fetch("ACMEVOKE_MAIL_DELIVERY_CONFIG_PORT", "25")

			unless cfg[:port] =~ /\A\d+\z/
				raise Acmevoke::Error::InvalidConfigError,
				      "Invalid value #{cfg[:port].inspect} specified in ACMEVOKE_MAIL_DELIVERY_CONFIG_PORT: must be a numeric port"
			end

			cfg[:port] = cfg[:port].to_i

			unless (1..65535).include?(cfg[:port])
				raise Acmevoke::Error::InvalidConfigError,
				      "Invalid port number #{cfg[:port]} specified in ACMEVOKE_MAIL_DELIVERY_CONFIG_PORT: must be between 1 and 65535 inclusive"
			end

			username = env.fetch("ACMEVOKE_MAIL_DELIVERY_CONFIG_USER_NAME", nil)
			password = env.fetch("ACMEVOKE_MAIL_DELIVERY_CONFIG_PASSWORD", nil)
			auth_method = env.fetch("ACMEVOKE_MAIL_DELIVERY_CONFIG_AUTH_METHOD", nil)

			if username && !password
				raise Acmevoke::Error::InvalidConfigError,
				      "Cannot authentication with only a username; set ACMEVOKE_MAIL_DELIVERY_CONFIG_PASSWORD or unset ACMEVOKE_MAIL_DELIVERY_CONFIG_USER_NAME"
			end

			if password && !username
				raise Acmevoke::Error::InvalidConfigError,
				      "Cannot authentication with only a username; set ACMEVOKE_MAIL_DELIVERY_CONFIG_USER_NAME or unset ACMEVOKE_MAIL_DELIVERY_CONFIG_PASSWORD"
			end

			if auth_method && !username
				raise Acmevoke::Error::InvalidConfigError,
				      "ACMEVOKE_MAIL_DELIVERY_CONFIG_AUTH_METHOD has no effect without a username and password to use"
			end

			if username && password
				cfg[:user_name] = username
				cfg[:password]  = password

				if auth_method
					if auth_method =~ /\Aplain|login|cram_md5\z/
						cfg[:authentication] = auth_method
					else
						raise Acmevoke::Error::InvalidConfigError,
						      "Invalid value #{auth_method.inspect} for ACMEVOKE_MAIL_DELIVERY_CONFIG_AUTH_METHOD; valid values are 'plain', 'login', or 'cram_md5'"
					end
				end
			end

			case (tls_val = env.fetch("ACMEVOKE_MAIL_DELIVERY_CONFIG_TLS", "always"))
			when "always"
				cfg[:enable_starttls] = true
			when "auto"
				cfg[:enable_starttls_auto] = true
			when "never"
				cfg[:enable_starttls_auto] = false
			when "smtps"
				cfg[:tls] = true
			else
				raise Acmevoke::Error::InvalidConfigError,
				      "Unrecognised value #{tls_val.inspect} for ACMEVOKE_MAIL_DELIVERY_CONFIG_TLS; must be one of 'always', 'auto', 'never', or 'smtps'"
			end

			case (verify_val = env.fetch("ACMEVOKE_MAIL_DELIVERY_CONFIG_TLS_VERIFY", "yes"))
			when /\A(y|yes|on|true|1)\z/i
				cfg[:openssl_verify_mode] = OpenSSL::SSL::VERIFY_PEER
			when /\A(n|no|off|false|0)\z/i
				cfg[:openssl_verify_mode] = OpenSSL::SSL::VERIFY_NONE
			else
				raise Acmevoke::Error::InvalidConfigError,
					"Unrecognised value #{verify_val.inspect} for ACMEVOKE_MAIL_DELIVERY_CONFIG_TLS_VERIFY; must be either 'yes' or 'no'"
			end
		end
	end

	def fetch_sendmail_delivery_config(env)
		{}.tap do |cfg|
			cfg[:location] = env.fetch("ACMEVOKE_MAIL_DELIVERY_CONFIG_SENDMAIL_PATH", "/usr/sbin/sendmail")
			cfg[:arguments] = Shellwords.split(env.fetch("ACMEVOKE_MAIL_DELIVERY_CONFIG_SENDMAIL_OPTIONS", "-i"))

			unless File.exists?(cfg[:location])
				raise Acmevoke::Error::InvalidConfigError,
				      "Specified sendmail path #{cfg[:location].inspect} does not exist"
			end

			unless File.executable?(cfg[:location])
				raise Acmevoke::Error::InvalidConfigError,
				      "Specified sendmail path is not an executable"
			end
		end
	end

	def fetch_file_delivery_config(env)
		{ location: env.fetch("ACMEVOKE_MAIL_DELIVERY_CONFIG_PATH", ".") }
	end
end
