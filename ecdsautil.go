package ecdsautil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	//"golang.org/x/crypto/blake2b"
	"github.com/dchest/blake2b"
	"io/ioutil"
	"log"
	"math/big"
	"os"
)

// Signature is a datatype for a ECDSA Signature
type Signature struct {
	R *big.Int
	S *big.Int
}

// NewKey - generates a new ECDSA Private Key
func NewKey() (privateKey *ecdsa.PrivateKey, err error) {
	privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	return
}

// MarshalPrivate - marshals a private key into PEM
func MarshalPrivate(privateKey *ecdsa.PrivateKey) (privKeyPEM []byte, err error) {
	x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return
	}
	// generate a HEADER with KeyID
	b, err := blake2b.New(&blake2b.Config{Size: 6})
	if err != nil {
		return
	}
	b.Write(x509Encoded)
	keyid := b.Sum(nil)
	pemEncoded := pem.EncodeToMemory(&pem.Block{
		Type: "EC PRIVATE KEY",
		Headers: map[string]string{
			"KeyID": fmt.Sprintf("%x", keyid),
		},
		Bytes: x509Encoded})
	return pemEncoded, nil
}

// MarshalPublic - marshals a public key
func MarshalPublic(publicKey *ecdsa.PublicKey) (pubKeyPEM []byte, err error) {
	x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return
	}
	// generate a HEADER with KeyID
	b, err := blake2b.New(&blake2b.Config{Size: 6})
	if err != nil {
		return
	}
	b.Write(x509EncodedPub)
	keyid := b.Sum(nil)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{
		Type: "EC PUBLIC KEY",
		Headers: map[string]string{
			"KeyID": fmt.Sprintf("%x", keyid),
		},
		Bytes: x509EncodedPub})
	return pemEncodedPub, nil
}

// UnmarshalPrivate - unmarshals a private key
func UnmarshalPrivate(privKeyPEM []byte) (privateKey *ecdsa.PrivateKey, err error) {
	block, _ := pem.Decode([]byte(privKeyPEM))
	x509Encoded := block.Bytes
	privateKey, err = x509.ParseECPrivateKey(x509Encoded)
	if err != nil {
		return
	}
	return
}

// UnmarshalPublic - unmarshals a public key
func UnmarshalPublic(pubKeyPEM []byte) (publicKey *ecdsa.PublicKey, err error) {
	blockPub, _ := pem.Decode([]byte(pubKeyPEM))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, err := x509.ParsePKIXPublicKey(x509EncodedPub)
	if err != nil {
		return
	}
	publicKey = genericPublicKey.(*ecdsa.PublicKey)
	return
}

// LoadPrivateKeyFromFile - loads a PEM encoded private key from disk
func LoadPrivateKeyFromFile(filename string) (privateKey *ecdsa.PrivateKey, err error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}
	// PEM decode data
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		err = fmt.Errorf("PEM block is not of type 'EC PRIVATE KEY'")
		return
	}
	if len(rest) > 0 {
		log.Printf("WARN: there is a rest left over from the private key PEM.")
	}
	// parse DER key
	privateKey, err = x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return
	}
	return
}

// LoadPublicKeyFromFile - loads a PEM encoded EC public key from disk
func LoadPublicKeyFromFile(filename string) (publicKey *ecdsa.PublicKey, err error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}
	// PEM decode data
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "EC PUBLIC KEY" {
		err = fmt.Errorf("PEM block is not of type 'EC PUBLIC KEY'")
		return
	}
	if len(rest) > 0 {
		log.Printf("WARN: there is a rest left over from the public key PEM.")
		log.Printf("      This usually means there are additional PEM blocks")
	}
	publicKeyIf, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return
	}
	publicKey = publicKeyIf.(*ecdsa.PublicKey)
	return
}

// SavePrivateKeyAsPEM - saves a given ECDSA private key to a file, PEM encoded.
// If the 'compat' flag is set to true it will save a key that is compatible with OpenSSL.
func SavePrivateKeyAsPEM(filename string, privateKey *ecdsa.PrivateKey, compat bool) (err error) {
	ecder, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return
	}
	keypem, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	// generate a HEADER with KeyID
	b, err := blake2b.New(&blake2b.Config{Size: 6})
	if err != nil {
		return
	}
	b.Write(ecder)
	keyid := b.Sum(nil)
	err = pem.Encode(keypem, &pem.Block{
		Type: "EC PRIVATE KEY",
		Headers: map[string]string{
			"KeyID": fmt.Sprintf("%x", keyid),
		},
		Bytes: ecder})
	if err != nil {
		return
	}
	if compat == true {
		ecp256r1, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
		if err != nil {
			return err
		}
		err = pem.Encode(keypem, &pem.Block{Type: "EC PARAMETERS", Bytes: ecp256r1})
		if err != nil {
			return err
		}
	}
	return
}

// SavePubKeyFromPrivate - saves the public key to a file.
// Takes filename and private key as argument, return error (if any)
func SavePubKeyFromPrivate(filename string, privateKey *ecdsa.PrivateKey) (err error) {
	publicKey := &privateKey.PublicKey
	x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return
	}

	keypem, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	// generate a HEADER with KeyID
	b, err := blake2b.New(&blake2b.Config{Size: 6})
	if err != nil {
		return
	}
	b.Write(x509EncodedPub)
	keyid := b.Sum(nil)
	err = pem.Encode(keypem, &pem.Block{
		Type: "EC PUBLIC KEY",
		Headers: map[string]string{
			"KeyID": fmt.Sprintf("%x", keyid),
		},
		Bytes: x509EncodedPub})
	if err != nil {
		return
	}
	return
}

func MarshalSignature(sig *Signature) (sigData []byte, err error) {
	sigData = sig.R.Bytes()
	sigData = append(sigData, sig.S.Bytes()...)
	return
}

func UnmarshalSignature(sigData []byte) (sig *Signature) {
	rh := sigData[0:32]
	sh := sigData[32:64]
	sig = SignatureFromBytes(rh, sh)
	return
}

// SignatureFromBytes - takes byte slices for s and r and returns a ECDSA Signature based on this.
func SignatureFromBytes(rb, sb []byte) (sig *Signature) {
	sig = new(Signature)
	sig.R = big.NewInt(0)
	sig.S = big.NewInt(0)
	sig.R = sig.R.SetBytes(rb)
	sig.S = sig.S.SetBytes(sb)
	return
}

// SaveSignatureToFile(filename string, signature *Signature) (err error)
// Saves a given ECDSA signature to a file.
func SaveSignatureToFile(filename string, signature *Signature) (err error) {
	data, err := MarshalSignature(signature)
	sigPem, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return
	}
	defer sigPem.Close()
	err = pem.Encode(sigPem, &pem.Block{Type: "EC SIGNATURE", Bytes: data})
	if err != nil {
		return
	}
	return
}

// LoadSignatureFromFile - loads a ECDSA Signature from file, DER encoded
func LoadSignatureFromFile(filename string) (sig *Signature, err error) {
	sig = new(Signature)
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}
	// PEM decode data
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "EC SIGNATURE" {
		err = fmt.Errorf("PEM block is not of type 'EC PUBLIC KEY'")
		return
	}
	if len(rest) > 0 {
		log.Printf("WARN: there is a rest left over from the public key PEM.")
		log.Printf("      This usually means there are additional PEM blocks")
	}
	sig = UnmarshalSignature(block.Bytes)
	return
}

// Verify - verifies a ECDSA signature against given data (usually a hash),
// useing the provided public key.
// This is basically just a wrapper around crypto/ecdsa.Verify()
func Verify(publicKey *ecdsa.PublicKey, hashBytes []byte, sig *Signature) (valid bool) {
	valid = ecdsa.Verify(publicKey, hashBytes, sig.R, sig.S)
	return
}

// Sign - signs given data with the provided private key, returns signature DER encoded.
// Basically just a wrapper around crypto/ecdsa.Sign
func Sign(privateKey *ecdsa.PrivateKey, hashBytes []byte) (sig *Signature, err error) {
	sig = &Signature{}
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashBytes)
	if err != nil {
		return
	}
	sig.R = r
	sig.S = s
	return sig, nil
}
