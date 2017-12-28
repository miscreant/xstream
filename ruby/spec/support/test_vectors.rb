# frozen_string_literal: true

require "tjson"

# Error parsing the example file
ParseError = Class.new(StandardError)

# rubocop:disable Style/ClassAndModuleChildren
class XStream::X25519HKDF::Example
  attr_reader :name, :alg, :sealingkey, :ephemeralkey, :salt, :blocks

  # Default file to load examples from
  DEFAULT_EXAMPLES = File.expand_path("../../../../vectors/xstream.tjson", __FILE__)

  # X25519 keypairs
  KeyPair = Struct.new(:seckey, :pubkey)

  # STREAM blocks
  Block = Struct.new(:ad, :plaintext, :ciphertext)

  def self.load_file(filename = DEFAULT_EXAMPLES)
    examples = TJSON.load_file(filename).fetch("examples")
    raise ParseError, "expected a toplevel array of examples" unless examples.is_a?(Array)

    examples.map { |example| new(example) }
  end

  def initialize(attrs)
    @name = attrs.fetch("name")
    @alg = attrs.fetch("alg")
    @sealingkey = KeyPair.new(
      attrs.fetch("sealingkey").fetch("seckey"),
      attrs.fetch("sealingkey").fetch("pubkey")
    )
    @ephemeralkey = KeyPair.new(
      attrs.fetch("ephemeralkey").fetch("seckey"),
      attrs.fetch("ephemeralkey").fetch("pubkey")
    )
    @salt = attrs["salt"]
    @blocks = attrs.fetch("blocks").map do |block|
      Block.new(
        block.fetch("ad"),
        block.fetch("plaintext"),
        block.fetch("ciphertext")
      )
    end
  end
end
# rubocop:enable Style/ClassAndModuleChildren
