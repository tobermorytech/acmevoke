# frozen_string_literal: true

guard 'rspec', cmd: "bundle exec rspec", all_on_start: true, all_after_pass: true do
  watch(%r{^spec/.+_spec\.rb$})
  watch(%r{^spec/.+_(methods|service|examples)\.rb$}) { 'spec' }
  watch(%r{^spec/fixtures})                           { 'spec' }
  watch('spec/spec_helper.rb')                        { 'spec' }
  watch(%r{^lib/})                                    { "spec" }
end
