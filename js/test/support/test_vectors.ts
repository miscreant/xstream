import * as fs from "async-file";
import TJSON from "tjson-js";

/** STREAM (AES-SIV/AES-PMAC-SIV) test vectors */
export class XStreamExample {
  static readonly DEFAULT_EXAMPLES_PATH = "../vectors/xstream.tjson";

  public readonly name: string;
  public readonly alg: string;
  public readonly ephemeralkey: XStreamKeypair;
  public readonly sealingkey: XStreamKeypair;
  public readonly salt: Uint8Array;
  public readonly blocks: XStreamBlock[];

  static async loadAll(): Promise<XStreamExample[]> {
    return XStreamExample.loadFromFile(XStreamExample.DEFAULT_EXAMPLES_PATH);
  }

  static async loadFromFile(filename: string): Promise<XStreamExample[]> {
    let tjson = TJSON.parse(await fs.readFile(filename, "utf8"));
    return tjson["examples"].map((ex: any) => {
      let obj = Object.create(XStreamExample.prototype);
      return Object.assign(obj, ex);
    });
  }
}

/** XSTREAM keypair */
export class XStreamKeypair {
  public readonly seckey: Uint8Array;
  public readonly pubkey: Uint8Array;
}

/** Test vector blocks in an XSTREAM */
export class XStreamBlock {
  public readonly ad: Uint8Array;
  public readonly plaintext: Uint8Array;
  public readonly ciphertext: Uint8Array;
}
