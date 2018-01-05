package xstream

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"
)

type xSTREAMExample struct {
	name         string
	alg          string
	sealingkey   xSTREAMKeypairExample
	ephemeralkey xSTREAMKeypairExample
	salt         []byte
	blocks       []xSTREAMBlockExample
}

type xSTREAMKeypairExample struct {
	pubkey []byte
	seckey []byte
}

type xSTREAMBlockExample struct {
	ad         []byte
	plaintext  []byte
	ciphertext []byte
}

func loadXSTREAMKeypairExample(k interface{}) xSTREAMKeypairExample {
	keypair := k.(map[string]interface{})

	pubkeyHex := keypair["pubkey:d16"].(string)
	pubkey := make([]byte, hex.DecodedLen(len(pubkeyHex)))

	if _, err := hex.Decode(pubkey, []byte(pubkeyHex)); err != nil {
		panic(err)
	}

	seckeyHex := keypair["seckey:d16"].(string)
	seckey := make([]byte, hex.DecodedLen(len(seckeyHex)))

	if _, err := hex.Decode(seckey, []byte(seckeyHex)); err != nil {
		panic(err)
	}

	return xSTREAMKeypairExample{pubkey, seckey}
}

// Load XSTREAM test vectors from xstream.tjson
// TODO: switch to a native Go TJSON parser when available
func loadXSTREAMExamples() []xSTREAMExample {
	var examplesJSON map[string]interface{}

	exampleData, err := ioutil.ReadFile("../vectors/xstream.tjson")
	if err != nil {
		panic(err)
	}

	if err = json.Unmarshal(exampleData, &examplesJSON); err != nil {
		panic(err)
	}

	examplesArray := examplesJSON["examples:A<O>"].([]interface{})

	if examplesArray == nil {
		panic("no toplevel 'examples:A<O>' key in aes_siv_stream.tjson")
	}

	result := make([]xSTREAMExample, len(examplesArray))

	for i, exampleJSON := range examplesArray {
		example := exampleJSON.(map[string]interface{})

		name := example["name:s"].(string)
		alg := example["alg:s"].(string)

		sealingkey := loadXSTREAMKeypairExample(example["sealingkey:O"])
		ephemeralkey := loadXSTREAMKeypairExample(example["ephemeralkey:O"])

		var salt []byte
		if example["salt:d16"] != nil {
			saltHex := example["salt:d16"].(string)
			salt = make([]byte, hex.DecodedLen(len(saltHex)))

			if _, err := hex.Decode(salt, []byte(saltHex)); err != nil {
				panic(err)
			}
		} else {
			salt = nil
		}

		blockValues := example["blocks:A<O>"].([]interface{})
		blocks := make([]xSTREAMBlockExample, len(blockValues))

		for j, blockJSON := range blockValues {
			block := blockJSON.(map[string]interface{})

			adHex := block["ad:d16"].(string)
			ad := make([]byte, hex.DecodedLen(len(adHex)))

			if _, err := hex.Decode(ad, []byte(adHex)); err != nil {
				panic(err)
			}

			plaintextHex := block["plaintext:d16"].(string)
			plaintext := make([]byte, hex.DecodedLen(len(plaintextHex)))

			if _, err := hex.Decode(plaintext, []byte(plaintextHex)); err != nil {
				panic(err)
			}

			ciphertextHex := block["ciphertext:d16"].(string)
			ciphertext := make([]byte, hex.DecodedLen(len(ciphertextHex)))

			if _, err := hex.Decode(ciphertext, []byte(ciphertextHex)); err != nil {
				panic(err)
			}

			blocks[j] = xSTREAMBlockExample{ad, plaintext, ciphertext}
		}

		result[i] = xSTREAMExample{name, alg, sealingkey, ephemeralkey, salt, blocks}
	}

	return result
}

// getEncryptionAlg returns the encryption algorithm string for a XSTREAM ciphersuite
func getEncryptionAlg(ciphersuite string) string {
	switch ciphersuite {
	case "XSTREAM_X25519_HKDF_SHA256_AES128_SIV":
		return "AES-SIV"
	case "XSTREAM_X25519_HKDF_SHA256_AES128_PMAC_SIV":
		return "AES-PMAC-SIV"
	default:
		panic("XSTREAM: unknown ciphersuite")
	}
}

func TestXSTREAMEncryptor(t *testing.T) {
	for _, v := range loadXSTREAMExamples() {
		fakerng := bytes.NewReader(v.ephemeralkey.seckey)
		var sealingkey [32]byte
		copy(sealingkey[:], v.sealingkey.pubkey)

		enc, ek, err := newEncryptorWithRNG(getEncryptionAlg(v.alg), &sealingkey, v.salt, fakerng)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(v.ephemeralkey.pubkey, ek[:]) {
			t.Errorf("NewEncryptor: expected: %x\ngot: %x", v.ephemeralkey.pubkey, ek[:])
		}

		for i, b := range v.blocks {
			lastBlock := i+1 == len(v.blocks)
			ct := enc.Seal(nil, b.plaintext, b.ad, lastBlock)
			if !bytes.Equal(b.ciphertext, ct) {
				t.Errorf("Seal: expected: %x\ngot: %x", b.ciphertext, ct)
			}
		}
	}
}

func TestXSTREAMDecryptor(t *testing.T) {
	for _, v := range loadXSTREAMExamples() {
		var sealingkey, ephemeralpub [32]byte
		copy(sealingkey[:], v.sealingkey.seckey)
		copy(ephemeralpub[:], v.ephemeralkey.pubkey)

		dec, err := NewDecryptor(getEncryptionAlg(v.alg), &sealingkey, &ephemeralpub, v.salt)
		if err != nil {
			t.Fatal(err)
		}

		for i, b := range v.blocks {
			lastBlock := i+1 == len(v.blocks)
			pt, err := dec.Open(nil, b.ciphertext, b.ad, lastBlock)

			if err != nil {
				t.Errorf("Open: %s", err)
			}

			if !bytes.Equal(b.plaintext, pt) {
				t.Errorf("Open: expected: %x\ngot: %x", b.plaintext, pt)
			}
		}
	}
}
