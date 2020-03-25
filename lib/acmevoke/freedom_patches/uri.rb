module Acmevoke::FreedomPatches::URI
	def join(p)
		if p[0] == "/"
			p = p[1..-1]
		end

		self.dup.tap do |u|
			if u.path[-1] == "/"
				u.path = u.path + p
			else
				u.path = u.path + "/" + p
			end
		end
	end
end

URI::Generic.prepend(Acmevoke::FreedomPatches::URI)
