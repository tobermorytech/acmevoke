require_relative "../spec_helper"

describe Acmevoke::Configuration do
	let(:config) { Acmevoke::Configuration.new(env) }
	let(:minimal_env) do
		{
			"ACMEVOKE_ISSUER_CERTIFICATES_FILE"          => fixture_dir("issuer_certs").join("ca").to_s,
			"ACMEVOKE_REDIS_URL"                         => "redis://localhost:6379",
			"ACMEVOKE_BASE_URL"                          => "https://acmevoke.example.com",
			"ACMEVOKE_REVOCATION_NOTIFICATION_SENDER"    => "acmevoke@example.com",
			"ACMEVOKE_REVOCATION_NOTIFICATION_RECIPIENT" => "revocation@example.com",
			"ACMEVOKE_MAIL_DELIVERY_METHOD"              => "test",
		}
	end

	context "with no env vars" do
		let(:env) { {} }

		it "fails to proceed" do
			expect { config }.to raise_error(Acmevoke::Error::InvalidConfigError)
		end
	end

	context "with a valid environment" do
		let(:env) { minimal_env }

		it "executes successfully" do
			expect { config }.to_not raise_error
		end
	end

	%w{ISSUER_CERTIFICATES_FILE REDIS_URL BASE_URL REVOCATION_NOTIFICATION_SENDER REVOCATION_NOTIFICATION_RECIPIENT MAIL_DELIVERY_METHOD}.each do |var|
		context "without ACMEVOKE_#{var}" do
			let(:env) { minimal_env.tap { |e| e.delete("ACMEVOKE_#{var}") } }

			it "fails to proceed" do
				expect { config }.to raise_error(Acmevoke::Error::InvalidConfigError, /ACMEVOKE_#{var}/)
			end
		end
	end

	context "ACMEVOKE_ISSUER_CERTIFICATES_FILE" do
		context "with a non-existent file" do
			let(:env) { minimal_env.merge("ACMEVOKE_ISSUER_CERTIFICATES_FILE" => "/if/this/path/exists/on/your/system/you/need/to/reconsider/your/life/choices") }

			it "fails to proceed" do
				expect { config }.to raise_error(Acmevoke::Error::InvalidConfigError, /ACMEVOKE_ISSUER_CERTIFICATES_FILE/)
			end
		end

		context "when pointing to an unreadable file" do
			let(:env) { minimal_env.merge("ACMEVOKE_ISSUER_CERTIFICATES_FILE" => "/etc/shadow") }

			it "fails to proceed" do
				expect { config }.to raise_error(Acmevoke::Error::InvalidConfigError, /ACMEVOKE_ISSUER_CERTIFICATES_FILE/)
			end
		end
	end

	context "ACMEVOKE_BASE_URL invalid" do
		let(:env) { minimal_env.merge("ACMEVOKE_BASE_URL" => "lol, this is totes not a URL!") }

		it "fails to proceed" do
			expect { config }.to raise_error(Acmevoke::Error::InvalidConfigError, /ACMEVOKE_BASE_URL/)
		end
	end

	context "ACMEVOKE_REVOCATION_NOTIFICATION_SENDER invalid" do
		let(:env) { minimal_env.merge("ACMEVOKE_REVOCATION_NOTIFICATION_SENDER" => "this totes isn't an e-mail, either!") }

		it "fails to proceed" do
			expect { config }.to raise_error(Acmevoke::Error::InvalidConfigError, /ACMEVOKE_REVOCATION_NOTIFICATION_SENDER/)
		end
	end

	context "ACMEVOKE_MAIL_DELIVERY_METHOD invalid" do
		let(:env) { minimal_env.merge("ACMEVOKE_MAIL_DELIVERY_METHOD" => "fred") }

		it "fails to proceed" do
			expect { config }.to raise_error(Acmevoke::Error::InvalidConfigError, /ACMEVOKE_MAIL_DELIVERY_METHOD/)
		end
	end

	context "ACMEVOKE_MAIL_DELIVERY_METHOD=smtp" do
		let(:base_env) { minimal_env.merge("ACMEVOKE_MAIL_DELIVERY_METHOD" => "smtp") }
		let(:env) { base_env }

		it "sets correct defaults" do
			expect(config.mail_delivery_config).to eq(
				address:             "localhost",
				port:                25,
				enable_starttls:     true,
				openssl_verify_mode: OpenSSL::SSL::VERIFY_PEER
			)
		end

		context "with TLS_VERIFY=no" do
			let(:env) { base_env.merge("ACMEVOKE_MAIL_DELIVERY_CONFIG_TLS_VERIFY" => "no") }

			it "sets the correct mail delivery config flag" do
				expect(config.mail_delivery_config[:openssl_verify_mode]).to eq(OpenSSL::SSL::VERIFY_NONE)
			end
		end

		context "with a non-default auth method" do
			let(:env) do
				base_env.merge(
					"ACMEVOKE_MAIL_DELIVERY_CONFIG_USER_NAME" => "bob",
					"ACMEVOKE_MAIL_DELIVERY_CONFIG_PASSWORD"  => "s3kr1t",
					"ACMEVOKE_MAIL_DELIVERY_CONFIG_AUTH_METHOD" => "cram_md5"
				)
			end

			it "sets the correct mail delivery config settings" do
				expect(config.mail_delivery_config[:user_name]).to eq("bob")
				expect(config.mail_delivery_config[:password]).to eq("s3kr1t")
				expect(config.mail_delivery_config[:authentication]).to eq("cram_md5")
			end
		end

		context "with TLS=auto" do
			let(:env) { base_env.merge("ACMEVOKE_MAIL_DELIVERY_CONFIG_TLS" => "auto") }

			it "sets the correct mail delivery config flag" do
				expect(config.mail_delivery_config[:enable_starttls_auto]).to eq(true)
			end
		end

		context "with TLS=never" do
			let(:env) { base_env.merge("ACMEVOKE_MAIL_DELIVERY_CONFIG_TLS" => "never") }

			it "sets the correct mail delivery config flag" do
				expect(config.mail_delivery_config[:enable_starttls_auto]).to eq(false)
			end
		end

		context "with TLS=smtps" do
			let(:env) { base_env.merge("ACMEVOKE_MAIL_DELIVERY_CONFIG_TLS" => "smtps") }

			it "sets the correct mail delivery config flag" do
				expect(config.mail_delivery_config[:tls]).to eq(true)
			end
		end

		{
			"when a non-numeric value for port is provided" => {
				"ACMEVOKE_MAIL_DELIVERY_CONFIG_PORT" => "forty-two",
			},
			"when a yuuuuuge numeric value for port is provided" => {
				"ACMEVOKE_MAIL_DELIVERY_CONFIG_PORT" => "314159625",
			},
			"when only a username is provided" => {
				"ACMEVOKE_MAIL_DELIVERY_CONFIG_USER_NAME" => "bob",
			},
			"when only a password is provided" => {
				"ACMEVOKE_MAIL_DELIVERY_CONFIG_PASSWORD" => "s3kr1t",
			},
			"when an auth method is specified without credentials" => {
				"ACMEVOKE_MAIL_DELIVERY_CONFIG_AUTH_METHOD" => "login",
			},
			"when an invalid auth method is given" => {
				"ACMEVOKE_MAIL_DELIVERY_CONFIG_USER_NAME" => "bob",
				"ACMEVOKE_MAIL_DELIVERY_CONFIG_PASSWORD" => "s3kr1t",
				"ACMEVOKE_MAIL_DELIVERY_CONFIG_AUTH_METHOD" => "asking nicely",
			},
			"when an invalid TLS mode is given" => {
				"ACMEVOKE_MAIL_DELIVERY_CONFIG_TLS" => "blind faith",
			},
			"when an invalid TLS verification mode is given" => {
				"ACMEVOKE_MAIL_DELIVERY_CONFIG_TLS_VERIFY" => "only if it's convenient",
			},
		}.each do |ctx, vars|
			context ctx do
				let(:env) { base_env.merge(vars) }

				it "fails to proceed" do
					expect { config }.to raise_error(Acmevoke::Error::InvalidConfigError)
				end
			end
		end
	end

	context "ACMEVOKE_MAIL_DELIVERY_METHOD=sendmail" do
		let(:base_env) { minimal_env.merge("ACMEVOKE_MAIL_DELIVERY_METHOD" => "sendmail") }
		let(:env) { base_env }

		context "by default" do
			it "sets correct defaults" do
				allow(File).to receive(:exists?).and_return(true)
				allow(File).to receive(:executable?).and_return(true)

				expect(config.mail_delivery_config).to eq(
					location:  "/usr/sbin/sendmail",
					arguments: ["-i"]
				)
			end
		end

		context "when a custom set of arguments is provided" do
			before(:each) do
				allow(File).to receive(:exists?).and_return(true)
				allow(File).to receive(:executable?).and_return(true)
			end

			let(:env) { base_env.merge("ACMEVOKE_MAIL_DELIVERY_CONFIG_SENDMAIL_OPTIONS" => "-p -q --start") }

			it "sets the config option correctly" do
				expect(config.mail_delivery_config[:arguments]).to eq(["-p", "-q", "--start"])
			end
		end

		{
			"when a non-existent sendmail path is provided" => {
				"ACMEVOKE_MAIL_DELIVERY_CONFIG_SENDMAIL_PATH" => "/i/hope/this/does/not/exist/on/your/system",
			},
			"when the sendmail path is not an executable file" => {
				"ACMEVOKE_MAIL_DELIVERY_CONFIG_SENDMAIL_PATH" => __FILE__,
			},
		}.each do |ctx, vars|
			context ctx do
				let(:env) { base_env.merge(vars) }

				it "fails to proceed" do
					expect { config }.to raise_error(Acmevoke::Error::InvalidConfigError)
				end
			end
		end
	end

	context "ACMEVOKE_MAIL_DELIVERY_METHOD=file" do
		let(:base_env) { minimal_env.merge("ACMEVOKE_MAIL_DELIVERY_METHOD" => "file") }
		let(:env) { base_env }

		it "sets correct defaults" do
			expect(config.mail_delivery_config).to eq(
				location:  "."
			)
		end

		context "when a custom path is provided" do
			let(:env) { base_env.merge("ACMEVOKE_MAIL_DELIVERY_CONFIG_PATH" => "/fred/bloggs") }

			it "sets the correct config" do
				expect(config.mail_delivery_config).to eq(location: "/fred/bloggs")
			end
		end
	end
end
