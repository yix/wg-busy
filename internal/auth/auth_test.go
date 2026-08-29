package auth

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yix/wg-busy/internal/models"
)

func TestSessionManager(t *testing.T) {
	sm := NewSessionManager()

	w := httptest.NewRecorder()
	token := sm.CreateSession(w)
	if token == "" {
		t.Fatalf("expected non-empty token")
	}

	resp := w.Result()
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected session cookie in response")
	}

	// Validate request with cookie
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookies[0])

	if !sm.ValidateSession(req) {
		t.Fatalf("expected session to be valid")
	}

	// Validate request with invalid cookie
	badReq := httptest.NewRequest("GET", "/", nil)
	badReq.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "invalid-token"})
	if sm.ValidateSession(badReq) {
		t.Fatalf("expected invalid cookie to fail validation")
	}

	// Clear session
	clearRecorder := httptest.NewRecorder()
	sm.ClearSession(clearRecorder, req)

	// Validate again after clearing
	if sm.ValidateSession(req) {
		t.Fatalf("expected cleared session to be invalid")
	}
}

func TestChallengeStore(t *testing.T) {
	cs := NewChallengeStore()

	ch, err := cs.GenerateChallenge()
	if err != nil {
		t.Fatalf("GenerateChallenge error: %v", err)
	}

	if ch == "" {
		t.Fatalf("expected non-empty challenge")
	}

	// First verify should succeed
	if !cs.VerifyAndConsume(ch) {
		t.Fatalf("expected challenge verification to succeed")
	}

	// Replay should fail
	if cs.VerifyAndConsume(ch) {
		t.Fatalf("expected replayed challenge verification to fail")
	}

	// Non-existent should fail
	if cs.VerifyAndConsume("non-existent") {
		t.Fatalf("expected non-existent challenge verification to fail")
	}
}

func TestWebAuthnRegistrationAndLogin_ES256(t *testing.T) {
	cs := NewChallengeStore()
	svc := NewWebAuthnService(cs)

	// 1. Begin Registration
	regOpts, err := svc.BeginRegistration("localhost", "WG Busy")
	if err != nil {
		t.Fatalf("BeginRegistration error: %v", err)
	}
	if regOpts.Challenge == "" {
		t.Fatalf("expected challenge in registration options")
	}

	// 2. Simulate Browser creating credential (ECDSA P-256)
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey error: %v", err)
	}
	pubKey := &privKey.PublicKey

	pubBytes, err := pubKey.Bytes()
	if err != nil {
		t.Fatalf("pubKey.Bytes error: %v", err)
	}
	xBytes := pubBytes[1:33]
	yBytes := pubBytes[33:65]

	// Simple CBOR map encoding for COSE EC2 key
	// Map(5) { 1: 2, 3: -7, -1: 1, -2: bstr(32), -3: bstr(32) }
	var coseBuf bytes.Buffer
	coseBuf.WriteByte(0xa5) // map of 5 pairs
	// 1: 2
	coseBuf.Write([]byte{0x01, 0x02})
	// 3: -7 (negative int -7 is 0x20 | 6 = 0x26)
	coseBuf.Write([]byte{0x03, 0x26})
	// -1: 1 (label -1 is 0x20 | 0 = 0x20)
	coseBuf.Write([]byte{0x20, 0x01})
	// -2: bstr(32) (label -2 is 0x20 | 1 = 0x21)
	coseBuf.Write([]byte{0x21, 0x58, 0x20})
	coseBuf.Write(xBytes)
	// -3: bstr(32) (label -3 is 0x20 | 2 = 0x22)
	coseBuf.Write([]byte{0x22, 0x58, 0x20})
	coseBuf.Write(yBytes)

	credID := []byte("test-credential-id-12345")
	credIDB64 := base64.RawURLEncoding.EncodeToString(credID)

	// Build authData: rpIdHash (32) + flags (1) + signCount (4) + aaguid (16) + credIdLen (2) + credID + coseKey
	rpIdHash := sha256.Sum256([]byte("localhost"))
	var authData bytes.Buffer
	authData.Write(rpIdHash[:])
	authData.WriteByte(0x41) // UP (0x01) | AT (0x40)
	authData.Write([]byte{0x00, 0x00, 0x00, 0x01}) // signCount = 1
	authData.Write(make([]byte, 16))               // zero AAGUID
	_ = binary.Write(&authData, binary.BigEndian, uint16(len(credID)))
	authData.Write(credID)
	authData.Write(coseBuf.Bytes())

	// Build attestationObject: Map { "authData": bstr, "fmt": "none", "attStmt": {} }
	var attObj bytes.Buffer
	attObj.WriteByte(0xa3) // map of 3 pairs
	// "authData": bytes
	attObj.Write([]byte{0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a'})
	attObj.WriteByte(0x58)
	attObj.WriteByte(byte(authData.Len()))
	attObj.Write(authData.Bytes())
	// "fmt": "none"
	attObj.Write([]byte{0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n', 'e'})
	// "attStmt": {}
	attObj.Write([]byte{0x67, 'a', 't', 't', 'S', 't', 'm', 't', 0xa0})

	clientData := ClientData{
		Type:      "webauthn.create",
		Challenge: regOpts.Challenge,
		Origin:    "http://localhost:8080",
	}
	clientDataJSON, _ := json.Marshal(clientData)

	regReq := RegistrationRequest{
		Name:  "Test MacBook Passkey",
		ID:    credIDB64,
		RawID: credIDB64,
		Type:  "public-key",
		Response: AuthenticatorAttestationResponse{
			ClientDataJSON:    base64.RawURLEncoding.EncodeToString(clientDataJSON),
			AttestationObject: base64.RawURLEncoding.EncodeToString(attObj.Bytes()),
		},
	}

	passkey, err := svc.FinishRegistration(regReq)
	if err != nil {
		t.Fatalf("FinishRegistration error: %v", err)
	}

	if passkey.Name != "Test MacBook Passkey" {
		t.Fatalf("unexpected passkey name: %s", passkey.Name)
	}
	if passkey.ID != credIDB64 {
		t.Fatalf("unexpected passkey ID: %s", passkey.ID)
	}

	// 3. Begin Login
	loginOpts, err := svc.BeginLogin("localhost", []models.Passkey{*passkey})
	if err != nil {
		t.Fatalf("BeginLogin error: %v", err)
	}
	if loginOpts.Challenge == "" {
		t.Fatalf("expected challenge in login options")
	}

	// 4. Simulate Browser signing assertion
	loginClientData := ClientData{
		Type:      "webauthn.get",
		Challenge: loginOpts.Challenge,
		Origin:    "http://localhost:8080",
	}
	loginClientDataJSON, _ := json.Marshal(loginClientData)
	loginClientDataHash := sha256.Sum256(loginClientDataJSON)

	// AuthData for assertion: rpIdHash (32) + flags (1) + signCount (4)
	var loginAuthData bytes.Buffer
	loginAuthData.Write(rpIdHash[:])
	loginAuthData.WriteByte(0x01) // UP
	loginAuthData.Write([]byte{0x00, 0x00, 0x00, 0x02}) // signCount = 2

	signedPayload := append(loginAuthData.Bytes(), loginClientDataHash[:]...)
	signedHash := sha256.Sum256(signedPayload)

	sig, err := ecdsa.SignASN1(rand.Reader, privKey, signedHash[:])
	if err != nil {
		t.Fatalf("ecdsa.SignASN1 error: %v", err)
	}

	authReq := AuthenticationRequest{
		ID:    credIDB64,
		RawID: credIDB64,
		Type:  "public-key",
		Response: AuthenticatorAssertionResponse{
			ClientDataJSON:    base64.RawURLEncoding.EncodeToString(loginClientDataJSON),
			AuthenticatorData: base64.RawURLEncoding.EncodeToString(loginAuthData.Bytes()),
			Signature:         base64.RawURLEncoding.EncodeToString(sig),
		},
	}

	authenticatedPasskey, err := svc.FinishLogin([]models.Passkey{*passkey}, authReq)
	if err != nil {
		t.Fatalf("FinishLogin error: %v", err)
	}

	if authenticatedPasskey.SignCount != 2 {
		t.Fatalf("expected signCount 2, got %d", authenticatedPasskey.SignCount)
	}
	if authenticatedPasskey.LastUsedAt == nil {
		t.Fatalf("expected LastUsedAt to be set")
	}
}

func TestWebAuthnLogin_RS256(t *testing.T) {
	cs := NewChallengeStore()
	svc := NewWebAuthnService(cs)

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey error: %v", err)
	}
	pubKey := &privKey.PublicKey

	// Encode COSE RSA key: Map(3) { 1: 3, 3: -257, -1: n (bytes), -2: e (bytes) }
	eBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(eBytes, uint32(pubKey.E))
	// Trim leading zeroes
	for len(eBytes) > 0 && eBytes[0] == 0 {
		eBytes = eBytes[1:]
	}

	var coseBuf bytes.Buffer
	coseBuf.WriteByte(0xa4) // map of 4 pairs
	// 1: 3
	coseBuf.Write([]byte{0x01, 0x03})
	// 3: -257 (neg int -257 = 0x39 0x01 0x00)
	coseBuf.Write([]byte{0x03, 0x39, 0x01, 0x00})
	// -1: n (label -1 = 0x20)
	coseBuf.Write([]byte{0x20, 0x59, 0x01, 0x00}) // bstr(256)
	coseBuf.Write(pubKey.N.Bytes())
	// -2: e (label -2 = 0x21)
	coseBuf.WriteByte(0x21)
	coseBuf.WriteByte(0x40 + byte(len(eBytes)))
	coseBuf.Write(eBytes)

	credID := []byte("rsa-cred-id")
	credIDB64 := base64.RawURLEncoding.EncodeToString(credID)

	passkey := models.Passkey{
		ID:        credIDB64,
		Name:      "RSA Key",
		PublicKey: base64.RawURLEncoding.EncodeToString(coseBuf.Bytes()),
		Algorithm: coseAlgRS256,
		CreatedAt: time.Now().UTC(),
	}

	loginOpts, err := svc.BeginLogin("localhost", []models.Passkey{passkey})
	if err != nil {
		t.Fatalf("BeginLogin error: %v", err)
	}

	loginClientData := ClientData{
		Type:      "webauthn.get",
		Challenge: loginOpts.Challenge,
		Origin:    "http://localhost:8080",
	}
	loginClientDataJSON, _ := json.Marshal(loginClientData)
	loginClientDataHash := sha256.Sum256(loginClientDataJSON)

	rpIdHash := sha256.Sum256([]byte("localhost"))
	var loginAuthData bytes.Buffer
	loginAuthData.Write(rpIdHash[:])
	loginAuthData.WriteByte(0x01)
	loginAuthData.Write([]byte{0x00, 0x00, 0x00, 0x05})

	signedPayload := append(loginAuthData.Bytes(), loginClientDataHash[:]...)
	signedHash := sha256.Sum256(signedPayload)

	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, signedHash[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15 error: %v", err)
	}

	authReq := AuthenticationRequest{
		ID:    credIDB64,
		RawID: credIDB64,
		Type:  "public-key",
		Response: AuthenticatorAssertionResponse{
			ClientDataJSON:    base64.RawURLEncoding.EncodeToString(loginClientDataJSON),
			AuthenticatorData: base64.RawURLEncoding.EncodeToString(loginAuthData.Bytes()),
			Signature:         base64.RawURLEncoding.EncodeToString(sig),
		},
	}

	authPasskey, err := svc.FinishLogin([]models.Passkey{passkey}, authReq)
	if err != nil {
		t.Fatalf("FinishLogin error: %v", err)
	}
	if authPasskey.SignCount != 5 {
		t.Fatalf("expected signCount 5, got %d", authPasskey.SignCount)
	}
}

func TestWebAuthnLogin_Ed25519(t *testing.T) {
	cs := NewChallengeStore()
	svc := NewWebAuthnService(cs)

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey error: %v", err)
	}

	// COSE OKP key: Map(4) { 1: 1, 3: -8, -1: 6, -2: pubKey (32 bytes) }
	var coseBuf bytes.Buffer
	coseBuf.WriteByte(0xa4)
	coseBuf.Write([]byte{0x01, 0x01})       // 1: 1 (OKP)
	coseBuf.Write([]byte{0x03, 0x27})       // 3: -8 (EdDSA)
	coseBuf.Write([]byte{0x20, 0x06})       // -1: 6 (Ed25519)
	coseBuf.Write([]byte{0x21, 0x58, 0x20}) // -2: bstr(32)
	coseBuf.Write(pubKey)

	credID := []byte("ed-cred-id")
	credIDB64 := base64.RawURLEncoding.EncodeToString(credID)

	passkey := models.Passkey{
		ID:        credIDB64,
		Name:      "Ed25519 Key",
		PublicKey: base64.RawURLEncoding.EncodeToString(coseBuf.Bytes()),
		Algorithm: coseAlgEdDSA,
		CreatedAt: time.Now().UTC(),
	}

	loginOpts, err := svc.BeginLogin("localhost", []models.Passkey{passkey})
	if err != nil {
		t.Fatalf("BeginLogin error: %v", err)
	}

	loginClientData := ClientData{
		Type:      "webauthn.get",
		Challenge: loginOpts.Challenge,
		Origin:    "http://localhost:8080",
	}
	loginClientDataJSON, _ := json.Marshal(loginClientData)
	loginClientDataHash := sha256.Sum256(loginClientDataJSON)

	rpIdHash := sha256.Sum256([]byte("localhost"))
	var loginAuthData bytes.Buffer
	loginAuthData.Write(rpIdHash[:])
	loginAuthData.WriteByte(0x01)
	loginAuthData.Write([]byte{0x00, 0x00, 0x00, 0x03})

	signedPayload := append(loginAuthData.Bytes(), loginClientDataHash[:]...)
	sig := ed25519.Sign(privKey, signedPayload)

	authReq := AuthenticationRequest{
		ID:    credIDB64,
		RawID: credIDB64,
		Type:  "public-key",
		Response: AuthenticatorAssertionResponse{
			ClientDataJSON:    base64.RawURLEncoding.EncodeToString(loginClientDataJSON),
			AuthenticatorData: base64.RawURLEncoding.EncodeToString(loginAuthData.Bytes()),
			Signature:         base64.RawURLEncoding.EncodeToString(sig),
		},
	}

	authPasskey, err := svc.FinishLogin([]models.Passkey{passkey}, authReq)
	if err != nil {
		t.Fatalf("FinishLogin error: %v", err)
	}
	if authPasskey.SignCount != 3 {
		t.Fatalf("expected signCount 3, got %d", authPasskey.SignCount)
	}
}
