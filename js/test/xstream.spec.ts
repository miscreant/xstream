import { suite, test } from "mocha-typescript";
import * as chai from "chai";
import * as chaiAsPromised from "chai-as-promised";
import { XStreamExample } from "./support/test_vectors";
import * as miscreant from "miscreant";
import * as xstream from "../src/index";

let expect = chai.expect;
chai.use(chaiAsPromised);

@suite class XStreamSpec {
  static provider: miscreant.ICryptoProvider;
  static vectors: XStreamExample[];

  static async before() {
    // NOTE: We use the PolyfillCryptoProvider for testing only, to avoid
    // installing the `node-webcrypto-ossl` package when testing under Node.
    //
    // Please use the (default) WebCryptoProvider in practice.
    // PolyfillCryptoProvider is not constant time
    this.provider = new miscreant.PolyfillCryptoProvider();
    this.vectors = await XStreamExample.loadAll();
  }

  @test async "seal() should pass test vectors"() {
    for (const v of XStreamSpec.vectors) {
      let encryptionAlg: string;

      // TODO: accept ciphersuite strings directly?
      switch (v.alg) {
        case "XSTREAM_X25519_HKDF_SHA256_AES128_SIV":
          encryptionAlg = "AES-SIV";
          break;
        case "XSTREAM_X25519_HKDF_SHA256_AES128_PMAC_SIV":
          encryptionAlg = "AES-PMAC-SIV";
          break;
        default:
          throw new Error(`invalid alg: ${v.alg}`);
      }

      const [encryptor, ephemeralPubKey] = await xstream.StreamEncryptor.generateFromPublicKey(
        v.sealingkey.pubkey,
        {
          salt: v.salt,
          encryptionAlg: encryptionAlg,
          provider: XStreamSpec.provider,
          rng: (arr: Uint8Array) => arr.set(v.ephemeralkey.seckey)
        });

      expect(ephemeralPubKey).to.eql(v.ephemeralkey.pubkey);

      for (const [i, b] of v.blocks.entries()) {
        const lastBlock = (i + 1 >= v.blocks.length);
        const sealed = await encryptor.seal(b.plaintext, lastBlock, b.ad);
        expect(sealed).to.eql(b.ciphertext);
      }

      expect(() => encryptor.clear()).not.to.throw();
    }
  }

  @test async "open() should pass test vectors"() {
    for (const v of XStreamSpec.vectors) {
      let encryptionAlg: string;

      switch (v.alg) {
        case "XSTREAM_X25519_HKDF_SHA256_AES128_SIV":
          encryptionAlg = "AES-SIV";
          break;
        case "XSTREAM_X25519_HKDF_SHA256_AES128_PMAC_SIV":
          encryptionAlg = "AES-PMAC-SIV";
          break;
        default:
          throw new Error(`invalid alg: ${v.alg}`);
      }

      const decryptor = await xstream.StreamDecryptor.generateFromKeys(
        v.sealingkey.seckey,
        v.ephemeralkey.pubkey,
        {
          salt: v.salt,
          encryptionAlg: encryptionAlg,
          provider: XStreamSpec.provider
        });

      for (const [i, b] of v.blocks.entries()) {
        const lastBlock = (i + 1 >= v.blocks.length);
        const unsealed = await decryptor.open(b.ciphertext, lastBlock, b.ad);
        expect(unsealed).not.to.be.null;
        expect(unsealed!).to.eql(b.plaintext);
      }

      expect(() => decryptor.clear()).not.to.throw();
    }
  }
}
