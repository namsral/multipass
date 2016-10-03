// Copyright 2016 Lars Wiegman. All rights reserved. Use of this source code is
// governed by a BSD-style license that can be found in the LICENSE file.

package multipass

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
)

// Portable constants
const (
	PKENV = "MULTIPASS_RSA_PRIVATE_KEY"
)

// PrivateKeyFromEnvironment returns the private key as indicated by the
// environment variable MULTIPASS_RSA_PRIVATE_KEY. The environment value must
// be a PEM encoding key starting with "-----BEGIN RSA PRIVATE KEY-----".
//
// A nil PrivateKey and nil error are returned if no private key is found in
// the environment variable value.
func PrivateKeyFromEnvironment() (*rsa.PrivateKey, error) {
	return pemDecodePrivateKey([]byte(os.Getenv(PKENV)))
}

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

func pemDecodePrivateKey(b []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, nil
	}
	pk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pk, nil
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
