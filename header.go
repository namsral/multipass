package multipass

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/textproto"
	"sort"
	"strings"
)

// Portable constants
const (
	DefaultDigest  = "SHA256"
	DefaultAlgo    = "RSASSA-PSS"
	DefaultKeySize = 2048
)

// Portable errors
var (
	ErrInvalidSignature = errors.New("invalid signature")
)

// copyHeader copies all headers from src to dst.
func copyHeader(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// formatHeaderParams serializes the given parameters and writes the parameter
// names in lower-case. It wraps the function mime.FormatMediaType from the
// standard library but drops the type.
func formatHeaderParams(params map[string]string) string {
	s := mime.FormatMediaType("a", params)
	if len(s) > 3 {
		s = s[3:]
	}
	return s
}

// parseHeaderParams parses the parameters in the given string.
// It wraps the function mime.ParseMediaType from the standard library and
// fakes the media type value.
func parseHeaderParams(s string) (params map[string]string, err error) {
	_, params, err = mime.ParseMediaType("42; " + s)
	return params, err
}

// SignHeader signs the given header and adds the key with name
// "Multipass-Signature".
// The signature is generated using the RSA_PSS algorithm and sha-256 digest.
func SignHeader(h http.Header, key *rsa.PrivateKey) error {
	rng := rand.Reader

	// TODO: reevaluate the hashing algorithm in 2017 as it might not be strong
	// enough.
	hashed := sha256.Sum256(ConcatonateHeader(h))

	signature, err := rsa.SignPSS(rng, key, crypto.SHA256, hashed[:], nil)
	if err != nil {
		return err
	}
	buf := new(bytes.Buffer)
	for k := range h {
		if buf.Len() > 0 {
			fmt.Fprint(buf, ",", k)
			continue
		}
		fmt.Fprint(buf, k)
	}

	params := map[string]string{
		"signed-headers": buf.String(),
		"algo":           DefaultAlgo,
		"digest":         DefaultDigest,
		"signature":      base64.StdEncoding.EncodeToString(signature),
	}
	h.Set("Multipass-Signature", formatHeaderParams(params))
	return nil
}

// VerifySignedHeader verifies the signed header with the given public key.
// It returns an erros when the key with name "Multipass-Signature" is not set.
func VerifySignedHeader(h http.Header, key *rsa.PublicKey) error {
	s := h.Get("Multipass-Signature")
	if s == "" {
		return ErrInvalidSignature
	}
	a, err := parseHeaderParams(s)
	if err != nil {
		return ErrInvalidSignature
	}
	if a["algo"] != DefaultAlgo {
		return ErrInvalidSignature
	}
	if a["digest"] != DefaultDigest {
		return ErrInvalidSignature
	}
	signature, err := base64.StdEncoding.DecodeString(a["signature"])
	if err != nil || len(signature) == 0 {
		return ErrInvalidSignature
	}

	headerToSign := make(http.Header)
	for _, k := range strings.Split(a["signed-headers"], ",") {
		headerToSign.Add(k, h.Get(k))
	}

	// TODO: reevaluate the hashing algorithm in 2017 as it might not be strong
	// enough.
	hashed := sha256.Sum256(ConcatonateHeader(headerToSign))

	if err := rsa.VerifyPSS(key, crypto.SHA256, hashed[:], signature, nil); err != nil {
		return err
	}
	return nil
}

// ConcatonateHeader returns concatination of the given headers.
// Headers are sorted, trimmed of whitespace, and converted to
// lowercase. Multiple headers with the same name are joined using commas to
// separate values.
func ConcatonateHeader(h http.Header) []byte {
	var keys sort.StringSlice
	var header = make(map[string][]string)
	for k, vs := range h {
		newKey := strings.ToLower(textproto.TrimString(k))
		var values []string
		if s, ok := header[newKey]; ok {
			values = s
		} else {
			keys = append(keys, newKey)
		}
		for _, v := range vs {
			values = append(values, textproto.TrimString(v))
		}
		if len(values) > 0 {
			header[newKey] = values
		}
	}
	buf := new(bytes.Buffer)
	keys.Sort()
	for i, k := range keys {
		if i > 0 {
			buf.WriteString("\n")
		}
		var s sort.StringSlice = header[k]
		s.Sort()
		fmt.Fprint(buf, k, ":", strings.Join(s, ","))
	}
	return buf.Bytes()
}
