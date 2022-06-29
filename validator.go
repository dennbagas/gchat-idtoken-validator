package gchatidtokenvalidator

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	// Bearer Tokens received by apps will always specify this issuer.
	chatIssuer string = "chat@system.gserviceaccount.com"

	// Url to obtain the public certificate for the issuer.
	publicCertUrlPrefix string = "https://www.googleapis.com/service_accounts/v1/metadata/x509/"
)

var (
	defaultValidator = &Validator{client: newCachingClient(http.DefaultClient)}
	// now aliases time.Now for testing.
	now = time.Now
)

// Payload represents a decoded payload of an ID Token.
type Payload struct {
	Issuer   string                 `json:"iss"`
	Audience string                 `json:"aud"`
	Expires  int64                  `json:"exp"`
	IssuedAt int64                  `json:"iat"`
	Subject  string                 `json:"sub,omitempty"`
	Claims   map[string]interface{} `json:"-"`
}

// Validator provides a way to validate Google ID Tokens with a user provided
// http.Client.
type Validator struct {
	client *cachingClient
}

// jwt represents the segments of a jwt and exposes convenience methods for
// working with the different segments.
type jwt struct {
	header    string
	payload   string
	signature string
}

// jwtHeader represents a parted jwt's header segment.
type jwtHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

// Validate is used to validate the provided idToken with a known Google cert
// URL. If audience is not empty the audience claim of the Token is validated.
// Upon successful validation a parsed token Payload is returned allowing the
// caller to validate any additional claims.
func Validate(ctx context.Context, idToken string, audience string) (*Payload, error) {
	// TODO(codyoss): consider adding a check revoked version of the api. See: https://pkg.go.dev/firebase.google.com/go/auth?tab=doc#Client.VerifyIDTokenAndCheckRevoked
	return defaultValidator.validate(ctx, idToken, audience)
}

func (v *Validator) validate(ctx context.Context, idToken string, audience string) (*Payload, error) {
	jwt, err := parseJWT(idToken)
	if err != nil {
		return nil, err
	}
	header, err := jwt.parsedHeader()
	if err != nil {
		return nil, err
	}
	payload, err := jwt.parsedPayload()
	if err != nil {
		return nil, err
	}
	sig, err := jwt.decodedSignature()
	if err != nil {
		return nil, err
	}

	if audience != "" && payload.Audience != audience {
		return nil, fmt.Errorf("idtoken: audience provided does not match aud claim in the JWT")
	}

	if now().Unix() > payload.Expires {
		return nil, fmt.Errorf("idtoken: token expired")
	}

	if err := v.validateRS256(ctx, header.KeyID, jwt.hashedContent(), sig); err != nil {
		return nil, err
	}

	return payload, nil
}

func (v *Validator) validateRS256(ctx context.Context, keyID string, hashedContent []byte, sig []byte) error {
	certResp, err := v.client.getCert(ctx, publicCertUrlPrefix+chatIssuer)
	if err != nil {
		return err
	}
	j, err := findMatchingKey(certResp, keyID)
	if err != nil {
		return err
	}

	block, _ := pem.Decode([]byte(*j))
	if block == nil {
		return fmt.Errorf("malformed certificate")
	}

	var cert *x509.Certificate
	cert, err = x509.ParseCertificate(block.Bytes)

	if err != nil {
		return err
	}

	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)
	return rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, hashedContent, sig)
}

func findMatchingKey(response *certResponse, keyID string) (*string, error) {
	if response == nil {
		return nil, fmt.Errorf("idtoken: cert response is nil")
	}

	// fmt.Print("YOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO ======== ")
	// fmt.Println(*response)

	if val, ok := (*response)[keyID]; ok {
		return &val, nil
	}

	return nil, fmt.Errorf("idtoken: could not find matching cert keyId for the token provided")
}

func parseJWT(idToken string) (*jwt, error) {
	segments := strings.Split(idToken, ".")
	if len(segments) != 3 {
		return nil, fmt.Errorf("idtoken: invalid token, token must have three segments; found %d", len(segments))
	}
	return &jwt{
		header:    segments[0],
		payload:   segments[1],
		signature: segments[2],
	}, nil
}

// decodedHeader base64 decodes the header segment.
func (j *jwt) decodedHeader() ([]byte, error) {
	dh, err := decode(j.header)
	if err != nil {
		return nil, fmt.Errorf("idtoken: unable to decode JWT header: %v", err)
	}
	return dh, nil
}

// decodedPayload base64 payload the header segment.
func (j *jwt) decodedPayload() ([]byte, error) {
	p, err := decode(j.payload)
	if err != nil {
		return nil, fmt.Errorf("idtoken: unable to decode JWT payload: %v", err)
	}
	return p, nil
}

// decodedPayload base64 payload the header segment.
func (j *jwt) decodedSignature() ([]byte, error) {
	p, err := decode(j.signature)
	if err != nil {
		return nil, fmt.Errorf("idtoken: unable to decode JWT signature: %v", err)
	}
	return p, nil
}

// parsedHeader returns a struct representing a JWT header.
func (j *jwt) parsedHeader() (jwtHeader, error) {
	var h jwtHeader
	dh, err := j.decodedHeader()
	if err != nil {
		return h, err
	}
	err = json.Unmarshal(dh, &h)
	if err != nil {
		return h, fmt.Errorf("idtoken: unable to unmarshal JWT header: %v", err)
	}
	return h, nil
}

// parsedPayload returns a struct representing a JWT payload.
func (j *jwt) parsedPayload() (*Payload, error) {
	var p Payload
	dp, err := j.decodedPayload()
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(dp, &p); err != nil {
		return nil, fmt.Errorf("idtoken: unable to unmarshal JWT payload: %v", err)
	}
	if err := json.Unmarshal(dp, &p.Claims); err != nil {
		return nil, fmt.Errorf("idtoken: unable to unmarshal JWT payload claims: %v", err)
	}
	return &p, nil
}

// hashedContent gets the SHA256 checksum for verification of the JWT.
func (j *jwt) hashedContent() []byte {
	signedContent := j.header + "." + j.payload
	hashed := sha256.Sum256([]byte(signedContent))
	return hashed[:]
}

func (j *jwt) String() string {
	return fmt.Sprintf("%s.%s.%s", j.header, j.payload, j.signature)
}

func decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
