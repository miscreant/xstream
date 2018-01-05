package xstream

import (
	"crypto/rand"
	"crypto/sha256"
	"github.com/miscreant/miscreant/go"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"hash"
	"io"
)

// hkdfInfo is the domain separation string passed as HKDF info
const hkdfInfo = "XSTREAM_X25519_HKDF"

// x25519KeySize is the size of an X25519 key (public or private)
const x25519KeySize = 32

// symmetricKeySize is the size of an AES-128 key * 2 (for SIV mode)
const symmetricKeySize = 32

// streamNoncePrefixSize is the size of a nonce we need to pass to STREAM
const streamNoncePrefixSize = 8

// NewEncryptor uses X25519 and HKDF to derive a symmetric encryption key and
// returns a miscreant.StreamEncryptor instance initialized with that key
func NewEncryptor(
	alg string,
	publicKey *[x25519KeySize]byte,
	salt []byte,
) (*miscreant.StreamEncryptor, *[x25519KeySize]byte, error) {
	return newEncryptorWithRNG(alg, publicKey, salt, rand.Reader)
}

// Internal function called from tests with a fake RNG which emits the test vector
func newEncryptorWithRNG(
	alg string,
	publicKey *[x25519KeySize]byte,
	salt []byte, csrng io.Reader,
) (*miscreant.StreamEncryptor, *[x25519KeySize]byte, error) {
	var ephemeralScalar, ephemeralPublic [x25519KeySize]byte

	// Generate a random scalar from the provided RNG
	_, err := io.ReadFull(csrng, ephemeralScalar[:])
	if err != nil {
		return nil, nil, err
	}

	// Perform an X25519 elliptic curve Diffie-Hellman operation and use
	// the resulting shared secret to derive a symmetric key (using HKDF)
	symmetricKey, err := kdf(sha256.New, &ephemeralScalar, publicKey, salt)
	if err != nil {
		return nil, nil, err
	}

	// Since we derive a unique key per XSTREAM, we don't need to pass a
	// symmetric nonce, so pass all zeroes
	var zeroNonce [streamNoncePrefixSize]byte

	enc, err := miscreant.NewStreamEncryptor(alg, symmetricKey[:], zeroNonce[:])
	if err != nil {
		return nil, nil, err
	}

	// Use fixed-base scalar multiplication to compute the ephemeral public key
	// from the ephemeral private scalar
	curve25519.ScalarBaseMult(&ephemeralPublic, &ephemeralScalar)

	// TODO: use a more secure zeroing method that won't be optimized away
	for i := range ephemeralScalar {
		ephemeralScalar[i] = 0
	}

	return enc, &ephemeralPublic, nil
}

// NewDecryptor returns a miscreant.StreamDecryptor encryptor instance  with the given
// cipher, nonce, and a key which must be twice as long  as an AES key, either
// 32 or 64 bytes to select AES-128 (AES-SIV-256)  or AES-256 (AES-SIV-512).
func NewDecryptor(alg string, privateKey, ephemeralPub *[x25519KeySize]byte, salt []byte) (*miscreant.StreamDecryptor, error) {
	// Perform an X25519 elliptic curve Diffie-Hellman operation and use
	// the resulting shared secret to derive a symmetric key (using HKDF)
	symmetricKey, err := kdf(sha256.New, privateKey, ephemeralPub, salt)
	if err != nil {
		return nil, err
	}

	// Since we derive a unique key per XSTREAM, we don't need to pass a
	// symmetric nonce, so pass all zeroes
	var zeroNonce [streamNoncePrefixSize]byte

	return miscreant.NewStreamDecryptor(alg, symmetricKey[:], zeroNonce[:])
}

// Perform an X25519 key exchange, deriving a symmetric key from the result
func kdf(hash func() hash.Hash, privateKey, ephemeralKey *[x25519KeySize]byte, salt []byte) (*[symmetricKeySize]byte, error) {
	var sharedSecret [x25519KeySize]byte

	// Perform an X25519 elliptic curve Diffie-Hellman operation
	curve25519.ScalarMult(&sharedSecret, privateKey, ephemeralKey)

	// Use the X25519 shared secret as input to HKDF
	hkdf := hkdf.New(hash, sharedSecret[:], salt, []byte(hkdfInfo))

	// Derive a symmetric key using HKDF
	var symmetricKey [symmetricKeySize]byte
	_, err := io.ReadFull(hkdf, symmetricKey[:])
	if err != nil {
		return nil, err
	}

	return &symmetricKey, nil
}
