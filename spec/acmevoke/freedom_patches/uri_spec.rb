require_relative "../../spec_helper"

describe URI do
	describe "#join" do
		context "on a URI with no path" do
			let(:uri) { URI("https://example.com") }

			it "inserts a slash after the host" do
				expect(uri.join("fred").to_s).to eq("https://example.com/fred")
			end
		end

		context "on a URI with the root path" do
			let(:uri) { URI("https://example.com/") }

			it "doesn't double slash" do
				expect(uri.join("fred").to_s).to eq("https://example.com/fred")
			end
		end

		context "on a URI with a path without a trailing slash" do
			let(:uri) { URI("https://example.com/foo") }

			it "inserts a slash between the path elements" do
				expect(uri.join("bar").to_s).to eq("https://example.com/foo/bar")
			end
		end

		context "on a URI whose path already ends in a slash" do
			let(:uri) { URI("https://example.com/baz/") }

			it "doesn't double the slash" do
				expect(uri.join("wombat").to_s).to eq("https://example.com/baz/wombat")
			end
		end

		context "when the path to be joined starts with a slash" do
			let(:uri) { URI("https://example.com/foo") }

			it "doesn't double the slash" do
				expect(uri.join("/bar").to_s).to eq("https://example.com/foo/bar")
			end
		end
	end
end
