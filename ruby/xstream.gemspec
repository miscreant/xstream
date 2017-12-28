# frozen_string_literal: true

require File.expand_path("lib/xstream/version", __dir__)

Gem::Specification.new do |spec|
  spec.name          = "xstream"
  spec.version       = XStream::VERSION
  spec.authors       = ["Tony Arcieri"]
  spec.email         = ["bascule@gmail.com"]
  spec.homepage      = "https://github.com/miscreant/xstream/"
  spec.summary       = "Public key encryption system combining X25519 Diffie-Hellman with the STREAM construction"
  spec.description = <<-DESCRIPTION.strip.gsub(/\s+/, " ")
    XSTREAM combines the X25519 Elliptic Curve Diffie-Hellman function"
    "with HKDF and the STREAM construction for streaming authenticated"
    "encryption. The result is an easy-to-use public key cryptosystem.
  DESCRIPTION
  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.required_ruby_version = ">= 2.2.2"

  spec.add_runtime_dependency "hkdf",      "~> 0.3"
  spec.add_runtime_dependency "miscreant", "~> 0.3"
  spec.add_runtime_dependency "x25519",    "~> 1.0"

  spec.add_development_dependency "bundler", "~> 1.16"
end
