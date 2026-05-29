package validator

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"hash"
	"math/big"
)

// verifyRSA verifies a PKCS#1 v1.5 RSA signature. _ is the hash bit-length;
// crypto.SHA256 is hardcoded for the RS256 path. Extending RS384/RS512 is a
// matter of mapping the alg to crypto.Hash + sha384.New / sha512.New.
func verifyRSA(key any, signed, sig []byte, h hash.Hash, bits int) error {
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("key is %T, want *rsa.PublicKey", key)
	}
	h.Reset()
	h.Write(signed)
	digest := h.Sum(nil)
	if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, digest, sig); err != nil {
		return err
	}
	return nil
}

// verifyECDSA verifies an ES256 signature. The wire format per RFC 7518
// §3.4 is the concatenation of R || S, each a fixed-length big-endian
// integer; we split, set, and Verify.
func verifyECDSA(key any, signed, sig []byte, h hash.Hash) error {
	ecKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("key is %T, want *ecdsa.PublicKey", key)
	}
	if len(sig)%2 != 0 {
		return fmt.Errorf("ecdsa signature length %d odd", len(sig))
	}
	half := len(sig) / 2
	r := new(big.Int).SetBytes(sig[:half])
	s := new(big.Int).SetBytes(sig[half:])
	h.Reset()
	h.Write(signed)
	digest := h.Sum(nil)
	if !ecdsa.Verify(ecKey, digest, r, s) {
		return fmt.Errorf("ecdsa signature did not verify")
	}
	return nil
}
