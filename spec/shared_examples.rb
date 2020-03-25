shared_examples "a successful JSON response" do
	it "is successful" do
		expect(last_response).to be_ok
	end

	it "serves a JSON blob" do
		expect(last_response["Content-Type"]).to eq("application/json")
	end

	it "is valid JSON" do
		expect { JSON.parse(last_response.body) }.to_not raise_error
	end

	it "serves a JSON object" do
		expect(JSON.parse(last_response.body)).to be_a(Hash)
	end
end

shared_examples "a problem report" do |status:, type:|
	it "is unsuccessful" do
		expect(last_response).to_not be_ok
	end

	it "is not found" do
		expect(last_response.status).to eq(status)
	end

	it "returns a problem-report" do
		expect(last_response["Content-Type"]).to eq("application/problem+json")
	end

	it "returns valid JSON" do
		expect { JSON.parse(last_response.body) }.to_not raise_error
	end

	it "serves a JSON object" do
		expect(JSON.parse(last_response.body)).to be_a(Hash)
	end

	it "includes the status in the problem report" do
		expect(JSON.parse(last_response.body)["status"]).to eq(status)
	end

	it "specifies the correct problem type" do
		expect(JSON.parse(last_response.body)["type"]).to eq(type)
	end
end

shared_examples "a nonce issuer" do
	it "includes a Replay-Nonce response header" do
		expect(last_response["Replay-Nonce"]).to_not be_nil
	end

	it "remembers the new nonce for later" do
		expect(mock_redis).to have_received(:setex).with("acmevoke:nonce:#{last_response["Replay-Nonce"]}", 300, "1")
	end
end
