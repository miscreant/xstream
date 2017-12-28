# encoding: binary
# frozen_string_literal: true

require "stringio"

RSpec.describe XStream::X25519HKDF do
  let(:test_vectors) { described_class::Example.load_file }

  context "Encryptor" do
    describe "seal" do
      it "passes all STREAM test vectors" do
        test_vectors.each do |ex|
          case ex.alg
          when "XSTREAM_X25519_HKDF_SHA256_AES128_SIV"
            encryption_alg = "AES-SIV"
            digest_alg = "SHA-256"
          when "XSTREAM_X25519_HKDF_SHA256_AES128_PMAC_SIV"
            encryption_alg = "AES-PMAC-SIV"
            digest_alg = "SHA-256"
          else raise "unknown algorithm in test vectors: #{ex.alg}"
          end

          encryptor, _ephemeral_pubkey = described_class::Encryptor.generate(
            ex.sealingkey.pubkey,
            encryption_alg: encryption_alg,
            digest_alg: digest_alg,
            salt: ex.salt,
            csrng: TestRNG.new(ex.ephemeralkey.seckey)
          )

          ex.blocks.each_with_index do |block, i|
            ciphertext = encryptor.seal(block.plaintext, ad: block.ad, last_block: i + 1 == ex.blocks.size)
            expect(ciphertext).to eq(block.ciphertext)
          end
        end
      end
    end
  end

  context "Decryptor" do
    describe "open" do
      it "passes all STREAM test vectors" do
        test_vectors.each do |ex|
          case ex.alg
          when "XSTREAM_X25519_HKDF_SHA256_AES128_SIV"
            encryption_alg = "AES-SIV"
            digest_alg = "SHA-256"
          when "XSTREAM_X25519_HKDF_SHA256_AES128_PMAC_SIV"
            encryption_alg = "AES-PMAC-SIV"
            digest_alg = "SHA-256"
          else raise "unknown algorithm in test vectors: #{ex.alg}"
          end

          decryptor = described_class::Decryptor.new(
            ex.sealingkey.seckey,
            ex.ephemeralkey.pubkey,
            encryption_alg: encryption_alg,
            digest_alg: digest_alg,
            salt: ex.salt
          )

          ex.blocks.each_with_index do |block, i|
            plaintext = decryptor.open(block.ciphertext, ad: block.ad, last_block: i + 1 == ex.blocks.size)
            expect(plaintext).to eq(block.plaintext)
          end
        end
      end
    end
  end

  # !!!TESTING-ONLY!!! (not) "RNG" that emits test vectors
  class TestRNG
    def initialize(data)
      @data = StringIO.new(data)
    end

    def random_bytes(n)
      @data.read(n)
    end
  end
end
