package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/scusi/ecdsautil"
	"io"
	"io/ioutil"
	"log"
	"os"
)

var (
	debug   bool
	err     error
	cmd     string
	keyFile string
	sigFile string
	inFile  string
	outFile string
)

func init() {
	flag.StringVar(&cmd, "cmd", "", "command to use (newKey, sign, verify)")
	flag.StringVar(&keyFile, "key", "", "key file to use")
	flag.StringVar(&sigFile, "sig", "", "sig file to use")
	flag.StringVar(&outFile, "out", "", "file to write output to")
	flag.StringVar(&inFile, "in", "", "file to get input from")
	flag.BoolVar(&debug, "debug", false, "spills debug info when true")
}

func main() {
	flag.Parse()
	switch cmd {
	case "newKey":

		privateKey, err := ecdsautil.NewKey()
		if err != nil {
			log.Fatal(err)
		}
		pemBytesPrivate, err := ecdsautil.MarshalPrivate(privateKey)
		if err != nil {
			log.Fatal(err)
		}
		if outFile == "" && keyFile == "" {
			log.Printf("privateKey PEM encoded: %s", pemBytesPrivate)
		} else if outFile == "" && keyFile != "" {
			err = ioutil.WriteFile(keyFile, pemBytesPrivate, os.FileMode(0600))
			if err != nil {
				log.Fatal(err)
			}
			err = ecdsautil.SavePubKeyFromPrivate(keyFile+".pub", privateKey)
			if err != nil {
				log.Fatal(err)
			}
		} else if outFile != "" && keyFile == "" {
			err = ioutil.WriteFile(outFile, pemBytesPrivate, os.FileMode(0600))
			if err != nil {
				log.Fatal(err)
			}
			err = ecdsautil.SavePubKeyFromPrivate(outFile+".pub", privateKey)
			if err != nil {
				log.Fatal(err)
			}
		}
	case "sign":
		// check keyfile
		if keyFile == "" {
			err = fmt.Errorf("no key specified, use '-key' switch")
			log.Fatal(err)
		}
		// load private key
		privKeyPEM, err := ioutil.ReadFile(keyFile)
		if err != nil {
			log.Fatal(err)
		}
		privateKey, err := ecdsautil.UnmarshalPrivate(privKeyPEM)
		if err != nil {
			log.Fatal(err)
		}
		// check inFile
		if inFile == "" {
			err = fmt.Errorf("no input file specified, use '-in' switch")
			log.Fatal(err)
		}
		// check sigFile presence
		if sigFile == "" {
			sigFile = inFile + ".sig"
		}
		// get sha256 hash from infile
		hash := sha256.New()
		in, err := os.Open(inFile)
		if err != nil {
			log.Fatal(err)
		}
		defer in.Close()
		io.Copy(hash, in)
		if debug {
			log.Printf("input file has sha256sum: %x\n", hash.Sum(nil))
		}
		// sign checksum with private key
		r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash.Sum(nil))
		Signature := new(ecdsautil.Signature)
		Signature.R = r
		Signature.S = s

		signature := r.Bytes()
		signature = append(signature, s.Bytes()...)
		if debug {
			log.Printf("value of r: %x, length r: %d\n", r.Bytes(), len(r.Bytes()))
			log.Printf("value of s: %x, length s: %d\n", s.Bytes(), len(s.Bytes()))
		}
		// output signature as hex string
		hexStr := hex.EncodeToString(signature)
		if debug {
			log.Printf("Signature as hex String: %s\n", hexStr)
		}
		// implementation for github.com/btcsuite/btcutil/base58
		b58Str := base58.Encode(signature)
		if err != nil {
			log.Fatal(err)
		}
		if debug {
			log.Printf("Signature as base58 String: %s\n", b58Str)
		}
		// output signature base64encoded
		sigStr := base64.StdEncoding.EncodeToString(signature)
		if debug {
			log.Printf("Signature as base64 String: %s\n", sigStr)
		}

		err = ecdsautil.SaveSignatureToFile(sigFile, Signature)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("signature for %s has been saved to %s\n", inFile, sigFile)
	case "verify":
		if keyFile == "" {
			err = fmt.Errorf("no key specified, use '-key' switch")
			log.Fatal(err)
		}
		// check inFile
		if inFile == "" {
			err = fmt.Errorf("no input file specified, use '-in' switch")
			log.Fatal(err)
		}
		// check sigFile
		if sigFile == "" {
			if debug {
				log.Printf("no sig file specified, try to use %s\n", inFile+".sig")
			}
			sigFile = inFile + ".sig"
		}
		// create sha256 hash of input file
		// get sha256 hash from infile
		hash := sha256.New()
		in, err := os.Open(inFile)
		if err != nil {
			log.Fatal(err)
		}
		defer in.Close()
		io.Copy(hash, in)
		if debug {
			log.Printf("input file has sha256sum: %x\n", hash.Sum(nil))
		}
		// read and parse signature
		sig, err := ecdsautil.LoadSignatureFromFile(sigFile)
		if err != nil {
			log.Fatal(err)
		}
		// load public key from file
		publicKey, err := ecdsautil.LoadPublicKeyFromFile(keyFile)
		if err != nil {
			log.Fatal(err)
		}
		// verify signature against sha256 checksum
		verify := ecdsa.Verify(publicKey, hash.Sum(nil), sig.R, sig.S)
		// output result
		if verify {
			fmt.Printf("Signature verified OK\n")
		} else {
			fmt.Printf("Signature NOT Verified\n")
		}
	}
}
