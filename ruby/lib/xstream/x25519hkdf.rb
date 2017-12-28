# encoding: binary
# frozen_string_literal: true

module XStream
  # XSTREAM with X25519 key agreement and HKDF as the key derivation function
  module X25519HKDF
    # Domain separation string passed as HKDF info
    HKDF_INFO = "XSTREAM_X25519_HKDF".freeze

    # Size of an AES-128 key * 2 (for SIV mode)
    SYMMETRIC_KEY_SIZE = 32

    # XSTREAM encryptor with X25519+HKDF key derivation
    class Encryptor < ::Miscreant::STREAM::Encryptor
      # Generate an XSTREAM encryptor object with a random ephemeral key
      #
      # @param public_key [String] 32-byte X25519 public key (i.e. compressed Montgomery-u coordinate)
      # @param encryption_alg [String] symmetric encryption algorithm to use with STREAM (default `"AES-PMAC-SIV"`)
      # @param digest_alg [String] digest algorithm to use with HKDF (default `"SHA256"`)
      # @param salt [String] (optional) salt value to pass to HKDF
      # @param csrng [#random_bytes] secure RNG to use to derive ephemeral X25519 key (default `SecureRandom`)
      #
      # @return [Array(XStream::X25519HKDF, String)] STREAM encryptor and ephemeral public key
      def self.generate(
        public_key,
        encryption_alg: "AES-PMAC-SIV",
        digest_alg: "SHA-256",
        salt: nil,
        csrng: SecureRandom
      )
        ephemeral_scalar = csrng.random_bytes(::X25519::KEY_SIZE)
        ephemeral_public = ::X25519.calculate_public_key(ephemeral_scalar)

        symmetric_key = X25519HKDF.kdf(
          ephemeral_scalar,
          public_key,
          salt: salt,
          digest_alg: digest_alg,
          output_size: SYMMETRIC_KEY_SIZE
        )

        stream = new(encryption_alg, symmetric_key, XStream::NONCE)
        [stream, ephemeral_public]
      end
    end

    # XSTREAM decryptor class with X25519+HKDF key derivation
    class Decryptor < ::Miscreant::STREAM::Decryptor
      # Create an XSTREAM decryptor object using our private key and an ephemeral public key
      #
      # @param private_key [String] 32-byte X25519 private key (i.e. private scalar)
      # @param ephemeral_public [String] 32-byte X25519 ephemeral public key from XSTREAM encryption
      # @param encryption_alg [String] symmetric encryption algorithm to use with STREAM (default `"AES-PMAC-SIV"`)
      # @param digest_alg [String] digest algorithm to use with HKDF (default `"SHA256"`)
      # @param salt [String] (optional) salt value to pass to HKDF
      def initialize(
          private_key,
          ephemeral_public,
          encryption_alg: "AES-PMAC-SIV",
          digest_alg: "SHA-256",
          salt: nil
      )
        # Perform an X25519 elliptic curve Diffie-Hellman operation and use
        # the resulting shared secret to derive a symmetric key (using HKDF)
        symmetric_key = X25519HKDF.kdf(
          private_key,
          ephemeral_public,
          salt: salt,
          digest_alg: digest_alg,
          output_size: SYMMETRIC_KEY_SIZE
        )

        super(encryption_alg, symmetric_key, XStream::NONCE)
      end
    end

    # Derive a symmetric encryption key from the combination of a public and
    # private key and salt using X25519 D-H and HKDF
    def self.kdf(private_key, public_key, output_size:, salt: nil, digest_alg: "SHA-256")
      raise ArgumentError, "invalid digest_alg: #{digest_alg}" unless digest_alg == "SHA-256"

      # Use X25519 to compute a shared secret
      shared_secret = X25519.diffie_hellman(private_key, public_key)

      # Use HKDF to derive a symmetric encryption key from the shared secret
      ::HKDF.new(
        shared_secret,
        salt: salt,
        info: HKDF_INFO,
        algorithm: "SHA256"
      ).next_bytes(output_size)
    end
  end
end
