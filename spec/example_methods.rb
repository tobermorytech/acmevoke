# frozen_string_literal: true

module ExampleMethods
	def fixture_dir(subdir)
		Pathname.new(__FILE__).join("..", "fixtures", subdir).tap do |p|
			unless p.directory?
				raise "Fixture dir #{subdir} does not exist"
			end
		end
	end
end
