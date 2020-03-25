# frozen_string_literal: true

require 'logger'

module ExampleGroupMethods
	def uses_redis
		let(:mock_redis) { instance_double(Redis) }

		before(:each) do
			allow(Redis).to receive(:new).and_return(mock_redis)
			allow(mock_redis).to receive(:setex).and_return("OK")
		end
	end
end
