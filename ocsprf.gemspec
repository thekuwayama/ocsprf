# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ocsp_response_fetch/version'

Gem::Specification.new do |spec|
  spec.name          = 'ocsprf'
  spec.version       = OCSPResponseFetch::VERSION
  spec.authors       = ['thekuwayama']
  spec.email         = ['thekuwayama@gmail.com']
  spec.summary       = 'OCSP Response Fetch'
  spec.description   = spec.summary
  spec.homepage      = 'https://github.com/thekuwayama/ocsprf'
  spec.license       = 'MIT'
  spec.required_ruby_version = '>=2.6.0'

  spec.files         = `git ls-files`.split($INPUT_RECORD_SEPARATOR)
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']
  spec.bindir        = 'exe'
  spec.executables   = ['ocsprf']

  spec.add_development_dependency 'bundler'
  spec.add_dependency             'fileutils'
  spec.add_dependency             'openssl'
end
