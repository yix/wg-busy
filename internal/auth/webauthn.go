package auth

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yix/wg-busy/internal/models"
)

// WebAuthn Creation & Request Option Structures

type CreationOptions struct {
	RP                     RelyingPartyEntity             `json:"rp"`
	User                   UserEntity                     `json:"user"`
	Challenge              string                         `json:"challenge"`
	PubKeyCredParams       []PubKeyCredParam              `json:"pubKeyCredParams"`
	Timeout                uint32                         `json:"timeout"`
	AuthenticatorSelection AuthenticatorSelectionCriteria `json:"authenticatorSelection"`
	Attestation            string                         `json:"attestation"`
}

type RelyingPartyEntity struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
}

type UserEntity struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type PubKeyCredParam struct {
	Type string `json:"type"`
	Alg  int64  `json:"alg"`
}

type AuthenticatorSelectionCriteria struct {
	ResidentKey      string `json:"residentKey,omitempty"`
	UserVerification string `json:"userVerification,omitempty"`
}

type RequestOptions struct {
	Challenge        string                      `json:"challenge"`
	Timeout          uint32                      `json:"timeout"`
	RPID             string                      `json:"rpId,omitempty"`
	AllowCredentials []AllowCredentialDescriptor `json:"allowCredentials,omitempty"`
	UserVerification string                      `json:"userVerification,omitempty"`
}

type AllowCredentialDescriptor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// WebAuthn Request JSON Payloads

type RegistrationRequest struct {
	Name     string                           `json:"name"`
	ID       string                           `json:"id"`
	RawID    string                           `json:"rawId"`
	Type     string                           `json:"type"`
	Response AuthenticatorAttestationResponse `json:"response"`
}

type AuthenticatorAttestationResponse struct {
	ClientDataJSON    string `json:"clientDataJSON"`
	AttestationObject string `json:"attestationObject"`
}

type AuthenticationRequest struct {
	ID       string                         `json:"id"`
	RawID    string                         `json:"rawId"`
	Type     string                         `json:"type"`
	Response AuthenticatorAssertionResponse `json:"response"`
}

type AuthenticatorAssertionResponse struct {
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle,omitempty"`
}

type ClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin,omitempty"`
}

// WebAuthnService manages WebAuthn ceremonies and verification.
type WebAuthnService struct {
	challenges *ChallengeStore
}

// NewWebAuthnService creates a new WebAuthnService with the given challenge store.
func NewWebAuthnService(challenges *ChallengeStore) *WebAuthnService {
	return &WebAuthnService{
		challenges: challenges,
	}
}

// DecodeBase64URL decodes a standard or unpadded base64url-encoded string.
func DecodeBase64URL(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	// Add padding if missing
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// BeginRegistration generates the PublicKeyCredentialCreationOptions for registration.
func (w *WebAuthnService) BeginRegistration(rpID, rpName string) (*CreationOptions, error) {
	challenge, err := w.challenges.GenerateChallenge()
	if err != nil {
		return nil, fmt.Errorf("generating challenge: %w", err)
	}

	if rpName == "" {
		rpName = "WG Busy"
	}

	opts := &CreationOptions{
		RP: RelyingPartyEntity{
			ID:   rpID,
			Name: rpName,
		},
		User: UserEntity{
			ID:          base64.RawURLEncoding.EncodeToString([]byte("admin")),
			Name:        "admin",
			DisplayName: "Administrator",
		},
		Challenge: challenge,
		PubKeyCredParams: []PubKeyCredParam{
			{Type: "public-key", Alg: coseAlgES256}, // -7: ES256
			{Type: "public-key", Alg: coseAlgRS256}, // -257: RS256
			{Type: "public-key", Alg: coseAlgEdDSA}, // -8: EdDSA
		},
		Timeout: 60000,
		AuthenticatorSelection: AuthenticatorSelectionCriteria{
			ResidentKey:      "preferred",
			UserVerification: "preferred",
		},
		Attestation: "none",
	}

	return opts, nil
}

// FinishRegistration parses and verifies the registration response and returns a new Passkey.
func (w *WebAuthnService) FinishRegistration(req RegistrationRequest) (*models.Passkey, error) {
	if req.ID == "" {
		return nil, errors.New("missing credential ID")
	}

	// 1. Decode & verify ClientDataJSON
	clientDataBytes, err := DecodeBase64URL(req.Response.ClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("decoding clientDataJSON: %w", err)
	}

	var clientData ClientData
	if err := json.Unmarshal(clientDataBytes, &clientData); err != nil {
		return nil, fmt.Errorf("parsing clientDataJSON: %w", err)
	}

	if clientData.Type != "webauthn.create" {
		return nil, fmt.Errorf("invalid clientData type: %q (expected webauthn.create)", clientData.Type)
	}

	if !w.challenges.VerifyAndConsume(clientData.Challenge) {
		return nil, errors.New("invalid or expired registration challenge")
	}

	// 2. Decode AttestationObject (CBOR)
	attestationBytes, err := DecodeBase64URL(req.Response.AttestationObject)
	if err != nil {
		return nil, fmt.Errorf("decoding attestationObject: %w", err)
	}

	attestationVal, err := DecodeCBOR(bytes.NewReader(attestationBytes))
	if err != nil {
		return nil, fmt.Errorf("decoding attestationObject CBOR: %w", err)
	}

	attMap, ok := attestationVal.(map[any]any)
	if !ok {
		return nil, errors.New("attestationObject is not a CBOR map")
	}

	authDataBytes, ok := attMap["authData"].([]byte)
	if !ok {
		return nil, errors.New("missing authData in attestationObject")
	}

	// 3. Parse authData
	// Minimum length with attested credential data: 37 (rpIdHash 32 + flags 1 + signCount 4) + 16 (AAGUID) + 2 (credIdLen) = 55
	if len(authDataBytes) < 55 {
		return nil, errors.New("authData too short")
	}

	flags := authDataBytes[32]
	const (
		flagUP = 0x01 // User Present
		flagAT = 0x40 // Attested credential data present
	)

	if flags&flagUP == 0 {
		return nil, errors.New("user was not present during registration")
	}
	if flags&flagAT == 0 {
		return nil, errors.New("authData missing attested credential data")
	}

	signCount := binary.BigEndian.Uint32(authDataBytes[33:37])
	aaguid := authDataBytes[37:53]
	credIDLen := binary.BigEndian.Uint16(authDataBytes[53:55])

	if len(authDataBytes) < 55+int(credIDLen) {
		return nil, errors.New("authData too short for credential ID")
	}

	credID := authDataBytes[55 : 55+credIDLen]
	credIDB64 := base64.RawURLEncoding.EncodeToString(credID)

	coseKeyBytes := authDataBytes[55+credIDLen:]
	coseKey, err := DecodeCOSEKeyFromBytes(coseKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing COSE key: %w", err)
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "Admin Passkey"
	}

	passkey := &models.Passkey{
		ID:        credIDB64,
		Name:      name,
		PublicKey: base64.RawURLEncoding.EncodeToString(coseKeyBytes),
		Algorithm: coseKey.Alg,
		SignCount: signCount,
		AAGUID:    hex.EncodeToString(aaguid),
		CreatedAt: time.Now().UTC(),
	}

	return passkey, nil
}

// BeginLogin generates the PublicKeyCredentialRequestOptions for authentication.
func (w *WebAuthnService) BeginLogin(rpID string, passkeys []models.Passkey) (*RequestOptions, error) {
	challenge, err := w.challenges.GenerateChallenge()
	if err != nil {
		return nil, fmt.Errorf("generating challenge: %w", err)
	}

	var allowCreds []AllowCredentialDescriptor
	for _, p := range passkeys {
		allowCreds = append(allowCreds, AllowCredentialDescriptor{
			Type: "public-key",
			ID:   p.ID,
		})
	}

	opts := &RequestOptions{
		Challenge:        challenge,
		Timeout:          60000,
		RPID:             rpID,
		AllowCredentials: allowCreds,
		UserVerification: "preferred",
	}

	return opts, nil
}

// FinishLogin verifies the authentication response against registered passkeys and returns the authenticated passkey.
func (w *WebAuthnService) FinishLogin(passkeys []models.Passkey, req AuthenticationRequest) (*models.Passkey, error) {
	if req.ID == "" {
		return nil, errors.New("missing credential ID")
	}

	// 1. Find matching passkey
	var matched *models.Passkey
	for i := range passkeys {
		if passkeys[i].ID == req.ID {
			matched = &passkeys[i]
			break
		}
	}
	if matched == nil {
		return nil, errors.New("passkey not registered")
	}

	// 2. Decode & verify ClientDataJSON
	clientDataBytes, err := DecodeBase64URL(req.Response.ClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("decoding clientDataJSON: %w", err)
	}

	var clientData ClientData
	if err := json.Unmarshal(clientDataBytes, &clientData); err != nil {
		return nil, fmt.Errorf("parsing clientDataJSON: %w", err)
	}

	if clientData.Type != "webauthn.get" {
		return nil, fmt.Errorf("invalid clientData type: %q (expected webauthn.get)", clientData.Type)
	}

	if !w.challenges.VerifyAndConsume(clientData.Challenge) {
		return nil, errors.New("invalid or expired authentication challenge")
	}

	// 3. Decode authenticatorData
	authDataBytes, err := DecodeBase64URL(req.Response.AuthenticatorData)
	if err != nil {
		return nil, fmt.Errorf("decoding authenticatorData: %w", err)
	}

	if len(authDataBytes) < 37 {
		return nil, errors.New("authenticatorData too short")
	}

	flags := authDataBytes[32]
	const flagUP = 0x01
	if flags&flagUP == 0 {
		return nil, errors.New("user was not present during authentication")
	}

	signCount := binary.BigEndian.Uint32(authDataBytes[33:37])

	// 4. Verify Signature
	sigBytes, err := DecodeBase64URL(req.Response.Signature)
	if err != nil {
		return nil, fmt.Errorf("decoding signature: %w", err)
	}

	coseKeyBytes, err := DecodeBase64URL(matched.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decoding stored passkey public key: %w", err)
	}

	coseKey, err := DecodeCOSEKeyFromBytes(coseKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing stored passkey public key: %w", err)
	}

	clientDataHash := sha256.Sum256(clientDataBytes)
	signedData := append(authDataBytes, clientDataHash[:]...)
	signedHash := sha256.Sum256(signedData)

	switch coseKey.Alg {
	case coseAlgES256:
		ecdsaPub, ok := coseKey.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("invalid ECDSA public key type")
		}
		if !ecdsa.VerifyASN1(ecdsaPub, signedHash[:], sigBytes) {
			return nil, errors.New("invalid ES256 passkey signature")
		}

	case coseAlgRS256:
		rsaPub, ok := coseKey.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("invalid RSA public key type")
		}
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, signedHash[:], sigBytes); err != nil {
			return nil, fmt.Errorf("invalid RS256 passkey signature: %w", err)
		}

	case coseAlgEdDSA:
		edPub, ok := coseKey.PublicKey.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("invalid Ed25519 public key type")
		}
		if !ed25519.Verify(edPub, signedData, sigBytes) {
			return nil, errors.New("invalid EdDSA passkey signature")
		}

	default:
		return nil, fmt.Errorf("unsupported COSE algorithm: %d", coseKey.Alg)
	}

	// Update signCount and last used timestamp
	updated := *matched
	updated.SignCount = signCount
	now := time.Now().UTC()
	updated.LastUsedAt = &now

	return &updated, nil
}
