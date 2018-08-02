package irisjwt

import (
	"fmt"
	"time"
	"sync"
	"bytes"
	"strconv"
	"io/ioutil"
	"encoding/json"
	"crypto/x509"
	"crypto/ecdsa"
	"crypto/sha256"
	"math/big"
	"encoding/base64"	
	"strings"
	"encoding/pem"
	"net/http"
)

var (
	mtx = &sync.RWMutex{}
	publicKeys = map[string]string{}
	x5u = ""
	httpClient *http.Client
)

// ServerLoginRequest structure for holding the request body to AUM login
type serverLoginRequest struct {
	Type string `json:"type"`
}

// ServerLoginResponse structure for holding the response from Iris AUM
type serverLoginResponse struct {
	ExpiresIn int64  `json:"expires_in"`
	Token			string `json:"token"`
}

func init() {
	// create http client object once - to be reused
	httpClient = &http.Client{Timeout: time.Duration(3 * time.Second)}
}

// Decoding
// Decode JWT specific base64url encoding with padding stripped
func Base64Decode(s string) ([]byte, error) {
	// add back missing padding
	switch len(s) % 4 {
	case 1:
		s += "==="
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// verifier -- wrapper
type verifier func(data []byte, signature []byte) (err error) 

func verifyWithSigner(token string, ver verifier) error { 
	parts := strings.Split(token, ".") 
	signedPart := []byte(strings.Join(parts[0:2], ".")) 
	signatureString, err := Base64Decode(parts[2]) 
	if err != nil {
		return fmt.Errorf("Unable to decode base64url encoded signature")  
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


// ValidatePublicKey is called to verify the signature which was created using ES256 algorithm.
// If the signature is verified and expiration time is validated, the function returns nil
// Otherwise, an error message is returned
func ValidatePublicKey(token string) error {
	parts := strings.Split(token, ".") 
	if len(parts) != 3 {
		return fmt.Errorf("token contains an invalid number of segments")
	}
	// HEADER
	h, err := Base64Decode(parts[0])
	if err != nil {
		return fmt.Errorf("Unable to decode base64url encoded header")
	}
	// Validate JWT header
	var header map[string]interface{}
	if err = json.Unmarshal([]byte(h), &header); err != nil {
		return fmt.Errorf("JSON error - Unable to unmarshal JWT header")
	}	
	// Validate header
	alg := header["alg"].(string)
	if alg != "ES256" {
		return fmt.Errorf("Algorithm not ES256. Failed authorization (%s)", alg)
	}
	// CLAIMS
	// Get JWT claims
	claimsStr, err := Base64Decode(parts[1])
	if err != nil {
		return fmt.Errorf("Unable to decode base64url encoded claims")
	}
	var claims map[string]interface{}
	if err = json.Unmarshal([]byte(claimsStr), &claims); err != nil {
		return fmt.Errorf("JSON error - Unable to unmarshal JWT claims")
	}

	// First, validate exp time
	// https://golang.org/pkg/encoding/json/#Unmarshal states that
	// JSON numbers are stored as float64 when unmarshaling JSON to an interface
	if _, ok := claims["exp"]; ok {
		exp := claims["exp"].(float64)
		if int64(exp) < time.Now().Unix() {
			return fmt.Errorf("JWT expired")
		} // else continue with scopes validation
	} else {
		return fmt.Errorf("unable to verify if claims has \"exp\" field")
	}
	
	// Now, get the public key and verify signature
	if _, ok := claims["app_key"]; !ok {
		return fmt.Errorf("unable to verify if claims has \"app_key\"")
	}
	
	// check if public ID is cached
	appKey := claims["app_key"].(string)
	var pk string
	mtx.RLock()
	if _, ok := publicKeys[appKey]; ok {
		pk = publicKeys[appKey]
	}
	mtx.RUnlock()	
	if len(pk) == 0 {
		publicKeyURI := x5u + "/" + claims["app_key"].(string) + ".pub"
		// Get the data
		resp, err := http.Get(publicKeyURI)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		// Writer the body to buffer
		pubKeyByte, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		pk = string(pubKeyByte[:])
		mtx.Lock()
		publicKeys[appKey] = pk
		mtx.Unlock()
	}
	// else public key is cached 
		
	decodedPEM, _ := pem.Decode([]byte(pk))
	if decodedPEM == nil {
		return fmt.Errorf("no PEM data is found")
	}
	pub, err := x509.ParsePKIXPublicKey(decodedPEM.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse DER encoded public key")
	}
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {        
		return fmt.Errorf("Value returned from ParsePKIXPublicKey is not an ECDSA public key")
	}
	return verifyEC(token, ecdsaPub)
}

// clear all cached public keys
func ClearAllCache() {
	mtx.Lock()
	defer mtx.Unlock()
	for k, _ := range publicKeys {
		delete(publicKeys, k)
	}
}


// clear cached public key
func ClearCache(appKey string) {
	mtx.Lock()
	defer mtx.Unlock()
	if _, ok := publicKeys[appKey]; ok {
		delete(publicKeys, appKey)
	}
}

// set the x5u URL from where th public keys can be retrieved
// Note that this should be done during the startup
func SetX5u(u string) {
	x5u = u
}

// retrieve scopes from JWT claims
func Scopes(token string) (string, error) {
	parts := strings.Split(token, ".") 
	if len(parts) != 3 {
		return "", fmt.Errorf("token contains an invalid number of segments")
	}
	
	// CLAIMS
	// Get JWT claims
	claimsStr, err := Base64Decode(parts[1])
	if err != nil {
		return "", err
	}
	var claims map[string]interface{}
	if err = json.Unmarshal([]byte(claimsStr), &claims); err != nil {
		return "", err
	}

	if _, ok := claims["scopes"]; ok {
		return claims["scopes"].(string), nil
	}
	return "", fmt.Errorf("JWT claims has no \"scopes\"")
}

// ValidateJwt is called to do basic sanity check on a JWT
// No validation of signature is done
func ValidateJwt(token string) error {
	parts := strings.Split(token, ".") 
	if len(parts) != 3 {
		return fmt.Errorf("token contains an invalid number of segments")
	}
	// HEADER
	h, err := Base64Decode(parts[0])
	if err != nil {
		return fmt.Errorf("%v - decode base64url encoded header", err)
	}
	// Validate JWT header
	var header map[string]interface{}
	if err = json.Unmarshal([]byte(h), &header); err != nil {
		return fmt.Errorf("%v - unmarshal JWT header", err)
	}	
	// Validate algorithm
	alg := header["alg"].(string)
	if alg != "ES256" {
		return fmt.Errorf("%v - \"alg\" value in JWT header must be \"ES256\"", alg)
	}
	// CLAIMS
	// Get JWT claims
	claimsStr, err := Base64Decode(parts[1])
	if err != nil {
		return fmt.Errorf("%v - decode base64url encoded claims", err)
	}
	var claims map[string]interface{}
	if err = json.Unmarshal([]byte(claimsStr), &claims); err != nil {
		return fmt.Errorf("%v - unmarshal JWT claims", err)
	}

	// First, validate exp time
	// https://golang.org/pkg/encoding/json/#Unmarshal states that
	// JSON numbers are stored as float64 when unmarshaling JSON to an interface
	if _, ok := claims["exp"]; ok {
		exp := claims["exp"].(float64)
		if int64(exp) < time.Now().Unix() {
			return fmt.Errorf("JWT expired")
		}
	} else {
		return fmt.Errorf("JWT claims does not have \"exp\" field")
	}
	
	// validate app_key exists
	if _, ok := claims["app_key"]; !ok {
		return fmt.Errorf("JWT claims does not have \"app_key\" field")
	}
	return nil	
}

// retrieve JWT expiry time
func JwtExpiryTime(token string) (int64, error) {
	parts := strings.Split(token, ".") 
	if len(parts) != 3 {
		return 0, fmt.Errorf("token contains an invalid number of segments")
	}
	// CLAIMS
	// Get JWT claims
	claimsStr, err := Base64Decode(parts[1])
	if err != nil {
		return 0, fmt.Errorf("%v - decode base64url encoded claims", err)
	}
	var claims map[string]interface{}
	if err = json.Unmarshal([]byte(claimsStr), &claims); err != nil {
		return 0, fmt.Errorf("%v - unmarshal JWT claims", err)
	}

	// First, validate exp time
	// https://golang.org/pkg/encoding/json/#Unmarshal states that
	// JSON numbers are stored as float64 when unmarshaling JSON to an interface
	if _, ok := claims["exp"]; ok {
		exp := claims["exp"].(float64)
		return int64(exp), nil
	}
	return 0, fmt.Errorf("JWT claims does not have \"exp\" field")
}

// fetches server JWT from AUm given key and secret
func GetServerJwt(u, k, s string) (int64, string, error) {
	authStr := "Basic " + base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", k, s)))
	body, err := json.Marshal(serverLoginRequest{Type: "Server"})
	if err != nil {
		return 0, "", fmt.Errorf("Error creating Server login request: %+v", err)
	}

	buff := bytes.NewBuffer(body)
	newPost, err := http.NewRequest("POST", u, buff)
	if err != nil {
		return 0, "", fmt.Errorf("Error creating login request: %+v", err)
	}

	newPost.Header.Set("Content-Length", strconv.Itoa(buff.Len()))
	newPost.Header.Set("Content-Type", "application/json")
	newPost.Header.Set("Authorization", authStr)

	resp, err := httpClient.Do(newPost)
	if err != nil {
		return 0, "", fmt.Errorf("Error obtaining server token: %+v", err)
	}

	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var r serverLoginResponse
		err = json.NewDecoder(resp.Body).Decode(&r)
		if err != nil {
			return 0, "", fmt.Errorf("Failed to parse response : %+v", err)
		}
		return r.ExpiresIn, r.Token, nil
	default:
		if resp.Header.Get("Content-Type") == "application/json" {
			var reason map[string]interface{}
			_ = json.NewDecoder(resp.Body).Decode(&reason)
			if err == nil {
				return 0, "", fmt.Errorf("httpCode: %v, reason: %+v", resp.StatusCode, reason["message"])
			}
		}
	}
	return 0, "", fmt.Errorf("Failed to obtain token: %s", resp.Status)
}
