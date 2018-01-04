/**
 * x25519hkdf.ts: Implementation of XSTREAM's core cryptographic primitive
 * combining X25519+HKDF+STREAM (XSTREAM_X25519_HKDF)
 */

// tslint:disable:max-classes-per-file

import { Hash } from "@stablelib/hash";
import { HKDF } from "@stablelib/hkdf";
import { SHA256 } from "@stablelib/sha256";
import { wipe } from "@stablelib/wipe";
import * as x25519 from "@stablelib/x25519";
import * as miscreant from "miscreant";

/** Domain separation string passed as HKDF info: "XSTREAM_X25519_HKDF" */
export const HKDF_INFO = new Uint8Array([88, 83, 84, 82, 69, 65, 77, 95, 88, 50, 53, 53, 49, 57, 95, 72, 75, 68, 70]);

/** Size of an AES-128 key * 2 (for SIV mode) */
export const SYMMETRIC_KEY_SIZE = 32;

/** STREAM nonce of all zeroes (since we always derive a unique key per STREAM) */
export const NONCE = new Uint8Array(8);

/** Default encryption algorithm to use */
export const DEFAULT_ENCRYPTION_ALG = "AES-PMAC-SIV";

/** Default digest algorithm to use */
export const DEFAULT_DIGEST_ALG = SHA256;

export interface IOptions {
  readonly encryptionAlg?: string;
  readonly digestAlg?: new () => Hash;
  readonly salt?: Uint8Array;
  readonly provider?: miscreant.ICryptoProvider;
  readonly rng?: (x: Uint8Array) => void;
}

/** An XSTREAM encryptor combining X25519 key exchange and HKDF for key derivation */
export class StreamEncryptor extends miscreant.StreamEncryptor {
  /** Create a new StreamEncryptor instance which seals data under the given public key */
  public static async generateFromPublicKey(
    publicKey: Uint8Array,
    options: IOptions = {},
  ): Promise<[StreamEncryptor, Uint8Array]> {
    const encryptionAlg = options.encryptionAlg || DEFAULT_ENCRYPTION_ALG;
    const digestAlg = options.digestAlg || DEFAULT_DIGEST_ALG;
    const rng = options.rng || window.crypto.getRandomValues;
    const provider = options.provider || new miscreant.WebCryptoProvider();

    const ephemeralScalar = new Uint8Array(x25519.SECRET_KEY_LENGTH);
    rng(ephemeralScalar);

    const symmetricKey = kdf(
      ephemeralScalar,
      publicKey,
      SYMMETRIC_KEY_SIZE,
      options.salt,
      digestAlg,
    );

    const ephemeralPublic = x25519.scalarMultBase(ephemeralScalar);
    wipe(ephemeralScalar);

    const encryptor = await super.importKey(symmetricKey, NONCE, encryptionAlg, provider);
    return [encryptor, ephemeralPublic];
  }
}

/** An XSTREAM decryptor combining X25519 key exchange and HKDF for key derivation */
export class StreamDecryptor extends miscreant.StreamDecryptor {
  /** Create a new StreamDecryptor instance with the given key */
  public static async generateFromKeys(
    privateKey: Uint8Array,
    ephemeralPublic: Uint8Array,
    options: IOptions = {},
  ): Promise<StreamDecryptor> {
    const encryptionAlg = options.encryptionAlg || DEFAULT_ENCRYPTION_ALG;
    const digestAlg = options.digestAlg || DEFAULT_DIGEST_ALG;
    const provider = options.provider || new miscreant.WebCryptoProvider();

    const symmetricKey = kdf(
      privateKey,
      ephemeralPublic,
      SYMMETRIC_KEY_SIZE,
      options.salt,
      digestAlg,
    );

    return super.importKey(symmetricKey, NONCE, encryptionAlg, provider);
  }
}

/**
 * Derive a symmetric encryption key from the combination of a public and
 * private key and salt using X25519 D-H and HKDF
 */
function kdf(
  privateKey: Uint8Array,
  publicKey: Uint8Array,
  outputLength: number,
  salt: Uint8Array | undefined,
  digestAlg: new () => Hash = DEFAULT_DIGEST_ALG,
): Uint8Array {
  const sharedSecret = x25519.scalarMult(privateKey, publicKey);
  return new HKDF(digestAlg, sharedSecret, salt, HKDF_INFO).expand(outputLength);
}
