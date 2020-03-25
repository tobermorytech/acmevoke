require "acmevoke"

config = Acmevoke::Configuration.new(ENV)

run Acmevoke::Application.new(config)
