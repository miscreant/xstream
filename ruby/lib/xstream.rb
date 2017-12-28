# encoding: binary
# frozen_string_literal: true

require "xstream/version"

require "securerandom"

require "hkdf"
require "miscreant"
require "x25519"

require "xstream/x25519hkdf"

# Public key encryption system combining X25519 Diffie-Hellman with the STREAM construction
module XStream
  # STREAM nonce of all zeroes (since we always derive a unique key per STREAM)
  NONCE = "\0\0\0\0\0\0\0\0".freeze

  # Default XSTREAM encryptor type
  Encryptor = X25519HKDF::Encryptor
end
