package multipass

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"testing"
)

func TestConcatonateHeader(t *testing.T) {
	tests := []struct {
		header map[string][]string
		expect []byte
	}{
		{
			header: map[string][]string{
				"a":   {"a2", "a1"},
				"b":   {"b1A", "b2", "b1B"},
				" B ": {"b3"},
			},
			expect: []byte("a:a1,a2\nb:b1A,b1B,b2,b3"),
		},
	}
	for i, test := range tests {
		got, want := ConcatonateHeader(test.header), test.expect
		if n := bytes.Compare(got, want); n != 0 {
			t.Errorf("test #%d; want %s, got %s", i, want, got)
		}
	}
}

func TestVerifySignedHeaderFail(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, DefaultKeySize)
	if err != nil {
		t.Error(err)
	}
	tests := []struct {
		params string
	}{
		{""},
		{"="},
		{"algo=1"},
		{fmt.Sprintf("algo=%s", DefaultAlgo)},
		{fmt.Sprintf("algo=%s; digest=%s", DefaultAlgo, DefaultDigest)},
		{fmt.Sprintf("algo=%s; digest=%s; signature=\"NDI=\"", DefaultAlgo, DefaultDigest)},
	}
	for i, test := range tests {
		h := make(http.Header)
		h.Set("Multipass-Signature", test.params)
		err := VerifySignedHeader(h, &pk.PublicKey)
		if err == nil {
			t.Errorf("test #%d; want %s, got %s", i, ErrInvalidSignature, err)
		}
	}
}

func TestSignAndVerifySignatureHander(t *testing.T) {
	h := make(http.Header)
	h.Add("Multipass-Handle", "leeloo@dallas")
	h.Add("Multipass-Origin", "127.0.0.2")
	pk, err := rsa.GenerateKey(rand.Reader, DefaultKeySize)
	if err != nil {
		t.Error(err)
	}
	if err := SignHeader(h, pk); err != nil {
		t.Error(err)
	}
	if err := VerifySignedHeader(h, &pk.PublicKey); err != nil {
		t.Error(err)
	}
}
