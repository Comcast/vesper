// Copyright 2017 Comcast Cable Communications Management, LLC

package main

import (
	"fmt"
	"time"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"encoding/base64"
	"strings"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"vesper/publickeys"
)

// ShakenHdr - structure that holds JWT header
type ShakenHdr struct {
	Alg string `json:"alg"`
	Ppt string `json:"ppt"`
	Typ string `json:"typ"`
	X5u string `json:"x5u"`
}

// base64Encode returns and Base64url encoded version of the input string with any
// trailing "=" stripped.
func base64Encode(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

// ---------------------------------------------------

// Decoding
// Decode JWT specific base64url encoding with padding stripped
func base64Decode(sig string) ([]byte, error) {
	// add back missing padding
	switch len(sig) % 4 {
	case 1:
		sig += "==="
	case 2:
		sig += "=="
	case 3:
		sig += "="
	}
	return base64.URLEncoding.DecodeString(sig)
}

// Encoding
// signer returns a signature for the given data.
type signer func(data []byte) (sig []byte, err error)

// EncodeWithSigner encodes a header and claim set with the provided signer.
func encodeWithSigner(header, claims []byte, sg signer) (string, string, error) {
	h := base64Encode(header)
	c := base64Encode(claims)
	ss := fmt.Sprintf("%s.%s", h, c)
	//logInfo("%v", ss)
	sig, err := sg([]byte(ss))
	if err != nil {
		return "", "", err
	}
	// return the header and claims as one string, signature part of JWT and error value
	return ss, fmt.Sprintf("%s", base64Encode(sig)), nil
}

// Encode encodes a signed JWS with provided header and claim set.
// This invokes EncodeWithSigner using crypto/ecdsa.Sign with the given EC private key.
// If only the signature component of PASSPORT is required, the boolean canon MUST be false
func encodeEC(header, claims []byte, key *ecdsa.PrivateKey) (string, string, error) {
	sg := func(data []byte) (sig []byte, err error) {
		h := sha256.New()
		r := big.NewInt(0)
		s := big.NewInt(0)
		h.Write([]byte(data))
		r,s,err = ecdsa.Sign(rand.Reader, key, h.Sum(nil))
		signature := r.Bytes()
 		signature = append(signature, s.Bytes()...)
		return signature, err
	}
	return encodeWithSigner(header, claims, sg)
}

type Verifier func(data []byte, signature []byte) (err error)

func verifyWithSigner(token string, ver Verifier) error {
	parts := strings.Split(token, ".")
	signedPart := []byte(strings.Join(parts[0:2], "."))
	signatureString, err := base64Decode(parts[2])
	if err != nil {
		return err
	}
	return ver(signedPart, []byte(signatureString))
}

func verifyEC(token string, key *ecdsa.PublicKey) error {
	ver := func(data []byte, signature []byte) (err error) {
		h := sha256.New()
		r := big.NewInt(0)
		s := big.NewInt(0)
		h.Write([]byte(data))
		r = new(big.Int).SetBytes(signature[:len(signature)/2])
		s = new(big.Int).SetBytes(signature[len(signature)/2:])
		if ecdsa.Verify(key, h.Sum(nil), r, s) {
			return nil
		}
		return fmt.Errorf("Unable to verify ES256 signature")
	}
	return verifyWithSigner(token, ver)
}


//------------------------------------------------------------------
// createSignature is called to create a JWT using ES256 algorithm.
// Note: The header and claims part of the created JWT is stripped out
//			 before returning the signature only
func createSignature(h, c []byte, p *ecdsa.PrivateKey) (string, string, error)  {
	canonical_string, sig, err := encodeEC(h, c, p)
	if err == nil {
		return canonical_string, sig, nil
	}
	return "", "", err
}

// verifySignature is called to verify the signature which was created
// using  ES256 algorithm.
// If the signature ois verified, the function returns nil. Otherwise,
// an error message is returned
func verifySignature(x5u, token string, verifyCA bool) (string, int, error) {
	// Get the data each time
	pk := publickeys.Fetch(x5u)
	if pk == nil {
		resp, err := http.Get(x5u)
		if err != nil {
			logError("%v", err)
			return "VESPER-4156", http.StatusBadRequest, err
		}
		defer resp.Body.Close()
		// Writer the body to buffer
		cert_buffer, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			logError("%v", err)
			return "VESPER-4157", http.StatusBadRequest, err
		}
		switch resp.StatusCode {
		case 200:
		default:
			return "VESPER-4156", http.StatusBadRequest, fmt.Errorf("%v", string(cert_buffer))
		}
		b := string(cert_buffer[:])
		block, _ := pem.Decode([]byte(b))
		if block == nil {
			err := fmt.Errorf("no PEM data is found")
			return "VESPER-4158", http.StatusBadRequest, err
		}
		// parse certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "VESPER-4159", http.StatusBadRequest, err
		}
		now := time.Now()
		opts := x509.VerifyOptions{CurrentTime: now,}
		if verifyCA {
			opts = x509.VerifyOptions{CurrentTime: now, Roots: rootCerts.Root(),}
		}
		if _, err := cert.Verify(opts); err != nil {
			switch err.Error() {
			case "x509: certificate has expired or is not yet valid":
				return "VESPER-4160", http.StatusBadRequest, err
			case "x509: certificate signed by unknown authority" :
				if verifyCA {
					return "VESPER-4161", http.StatusBadRequest, err
				}
			case "x509: certificate is not authorized to sign other certificates":
				if verifyCA {
					return "VESPER-4162", http.StatusBadRequest, err
				}
			case "x509: issuer name does not match subject from issuing certificate":
				if verifyCA {
					return "VESPER-4163", http.StatusBadRequest, err
				}
			default:
				if verifyCA {
					return "VESPER-4164", http.StatusBadRequest, err
				}
			}
		}
		// ES256
		var ok bool
		pk, ok = cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			err = fmt.Errorf("Value returned from ParsePKIXPublicKey was not an ECDSA public key")
			return "VESPER-4165", http.StatusBadRequest, err
		}
		// add to cache
		publickeys.Add(x5u, pk)
	}
	err := verifyEC(token, pk)
	if err != nil {
		return "VESPER-4166", http.StatusUnauthorized, err
	}
	return "", http.StatusOK, nil
}
