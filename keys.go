package multipass

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
)

// Portable constants
const (
	PKENV = "MULTIPASS_RSA_PRIVATE_KEY"
)

func pemEncodePrivateKey(w io.Writer, key *rsa.PrivateKey) error {
	data := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: data,
	}
	if err := pem.Encode(w, block); err != nil {
		return err
	}
	return nil
}

func pemDecodePrivateKey(b []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil
	}
	pk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil
	}
	return pk
}

func pemEncodePublicKey(w io.Writer, key *rsa.PublicKey) error {
	data, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: data,
	}
	if err := pem.Encode(w, block); err != nil {
		return err
	}
	return nil
}
