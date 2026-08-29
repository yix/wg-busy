package handlers

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/yix/wg-busy/internal/auth"
	"github.com/yix/wg-busy/internal/config"
	"github.com/yix/wg-busy/internal/models"
)

func testKey(prefix string) string { return prefix + strings.Repeat("A", 42) + "=" }

func setupTestStore(t *testing.T) (*config.Store, string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	wgPath := filepath.Join(dir, "wg0.conf")

	initial := `
server:
  privateKey: ` + testKey("A") + `
  listenPort: 51820
  address: 10.0.0.1/24
peers: []
`
	if err := os.WriteFile(cfgPath, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}

	store, err := config.Load(cfgPath, wgPath)
	if err != nil {
		t.Fatal(err)
	}
	return store, cfgPath
}

func generateTestCOSEKey(t *testing.T) (*ecdsa.PrivateKey, []byte, string) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &privKey.PublicKey
	xBytes := pubKey.X.Bytes()
	yBytes := pubKey.Y.Bytes()
	if len(xBytes) < 32 {
		pad := make([]byte, 32-len(xBytes))
		xBytes = append(pad, xBytes...)
	}
	if len(yBytes) < 32 {
		pad := make([]byte, 32-len(yBytes))
		yBytes = append(pad, yBytes...)
	}

	var coseBuf bytes.Buffer
	coseBuf.WriteByte(0xa5)
	coseBuf.Write([]byte{0x01, 0x02})
	coseBuf.Write([]byte{0x03, 0x26})
	coseBuf.Write([]byte{0x20, 0x01})
	coseBuf.Write([]byte{0x21, 0x58, 0x20})
	coseBuf.Write(xBytes)
	coseBuf.Write([]byte{0x22, 0x58, 0x20})
	coseBuf.Write(yBytes)

	credID := []byte("test-cred-id-" + base64.RawURLEncoding.EncodeToString(xBytes[:8]))
	credIDB64 := base64.RawURLEncoding.EncodeToString(credID)
	return privKey, coseBuf.Bytes(), credIDB64
}

func buildAttestation(credIDB64 string, coseKeyBytes []byte) string {
	credID, _ := auth.DecodeBase64URL(credIDB64)
	rpIdHash := sha256.Sum256([]byte("localhost"))
	var authData bytes.Buffer
	authData.Write(rpIdHash[:])
	authData.WriteByte(0x41) // UP | AT
	authData.Write([]byte{0x00, 0x00, 0x00, 0x01})
	authData.Write(make([]byte, 16)) // AAGUID
	binary.Write(&authData, binary.BigEndian, uint16(len(credID)))
	authData.Write(credID)
	authData.Write(coseKeyBytes)

	var attObj bytes.Buffer
	attObj.WriteByte(0xa3)
	attObj.Write([]byte{0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a'})
	attObj.WriteByte(0x58)
	attObj.WriteByte(byte(authData.Len()))
	attObj.Write(authData.Bytes())
	attObj.Write([]byte{0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n', 'e'})
	attObj.Write([]byte{0x67, 'a', 't', 't', 'S', 't', 'm', 't', 0xa0})

	return base64.RawURLEncoding.EncodeToString(attObj.Bytes())
}

func TestAuthStatusAndRegistration(t *testing.T) {
	store, _ := setupTestStore(t)
	router := NewRouter(store, fstest.MapFS{"index.html": {Data: []byte("html")}}, nil, nil, "dev")

	// 1. Initial auth status
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/auth/status", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var status authStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.RequirePasskey || status.HasPasskeys || status.PasskeyCount != 0 || !status.Authenticated {
		t.Fatalf("unexpected initial auth status: %#v", status)
	}

	// 2. Begin Passkey Registration
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/api/auth/passkeys/begin", nil)
	req.Host = "localhost:8080"
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var creationOpts auth.CreationOptions
	if err := json.Unmarshal(rec.Body.Bytes(), &creationOpts); err != nil {
		t.Fatal(err)
	}
	if creationOpts.Challenge == "" {
		t.Fatalf("expected challenge in creation options")
	}

	// 3. Finish Passkey Registration
	privKey, coseBytes, credIDB64 := generateTestCOSEKey(t)
	attObjB64 := buildAttestation(credIDB64, coseBytes)

	clientData := auth.ClientData{
		Type:      "webauthn.create",
		Challenge: creationOpts.Challenge,
		Origin:    "http://localhost:8080",
	}
	clientDataJSON, _ := json.Marshal(clientData)

	regReq := auth.RegistrationRequest{
		Name:  "Primary YubiKey",
		ID:    credIDB64,
		RawID: credIDB64,
		Type:  "public-key",
		Response: auth.AuthenticatorAttestationResponse{
			ClientDataJSON:    base64.RawURLEncoding.EncodeToString(clientDataJSON),
			AttestationObject: attObjB64,
		},
	}
	regBody, _ := json.Marshal(regReq)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/api/auth/passkeys/finish", bytes.NewReader(regBody))
	req.Host = "localhost:8080"
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from finish registration, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify session cookie was set
	cookies := rec.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == auth.SessionCookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatalf("expected session cookie upon registering initial passkey")
	}

	// Check store has passkey
	var passkeys []models.Passkey
	store.Read(func(cfg *models.AppConfig) {
		passkeys = append([]models.Passkey(nil), cfg.Server.Passkeys...)
	})
	if len(passkeys) != 1 || passkeys[0].Name != "Primary YubiKey" || passkeys[0].ID != credIDB64 {
		t.Fatalf("unexpected store passkeys: %#v", passkeys)
	}

	// 4. Enable RequirePasskey on Server
	form := url.Values{
		"listenPort":     {"51820"},
		"address":        {"10.0.0.1/24"},
		"requirePasskey": {"on"},
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("PUT", "/server", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(sessionCookie)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK saving server config, got %d: %s", rec.Code, rec.Body.String())
	}

	// 5. Test unauthenticated request is blocked with 401
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/peers", nil)
	req.Header.Set("HX-Request", "true")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for unauthenticated HTMX request, got %d", rec.Code)
	}

	// 6. Test authenticated request succeeds
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/peers", nil)
	req.Header.Set("HX-Request", "true")
	req.AddCookie(sessionCookie)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for authenticated HTMX request, got %d", rec.Code)
	}

	// 7. Test Login Flow
	// Begin Login
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/api/auth/login/begin", nil)
	req.Host = "localhost:8080"
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on login begin, got %d: %s", rec.Code, rec.Body.String())
	}

	var reqOpts auth.RequestOptions
	if err := json.Unmarshal(rec.Body.Bytes(), &reqOpts); err != nil {
		t.Fatal(err)
	}

	// Finish Login
	loginClientData := auth.ClientData{
		Type:      "webauthn.get",
		Challenge: reqOpts.Challenge,
		Origin:    "http://localhost:8080",
	}
	loginClientDataJSON, _ := json.Marshal(loginClientData)
	loginClientDataHash := sha256.Sum256(loginClientDataJSON)

	rpIdHash := sha256.Sum256([]byte("localhost"))
	var loginAuthData bytes.Buffer
	loginAuthData.Write(rpIdHash[:])
	loginAuthData.WriteByte(0x01) // UP
	loginAuthData.Write([]byte{0x00, 0x00, 0x00, 0x02})

	signedPayload := append(loginAuthData.Bytes(), loginClientDataHash[:]...)
	signedHash := sha256.Sum256(signedPayload)
	sig, err := ecdsa.SignASN1(rand.Reader, privKey, signedHash[:])
	if err != nil {
		t.Fatal(err)
	}

	authReq := auth.AuthenticationRequest{
		ID:    credIDB64,
		RawID: credIDB64,
		Type:  "public-key",
		Response: auth.AuthenticatorAssertionResponse{
			ClientDataJSON:    base64.RawURLEncoding.EncodeToString(loginClientDataJSON),
			AuthenticatorData: base64.RawURLEncoding.EncodeToString(loginAuthData.Bytes()),
			Signature:         base64.RawURLEncoding.EncodeToString(sig),
		},
	}
	authReqBody, _ := json.Marshal(authReq)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/api/auth/login/finish", bytes.NewReader(authReqBody))
	req.Host = "localhost:8080"
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on login finish, got %d: %s", rec.Code, rec.Body.String())
	}

	newCookies := rec.Result().Cookies()
	var newSessionCookie *http.Cookie
	for _, c := range newCookies {
		if c.Name == auth.SessionCookieName {
			newSessionCookie = c
			break
		}
	}
	if newSessionCookie == nil {
		t.Fatalf("expected new session cookie on login finish")
	}

	// 8. Delete Passkey
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("DELETE", "/api/auth/passkeys/"+credIDB64, nil)
	req.AddCookie(newSessionCookie)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on passkey delete, got %d: %s", rec.Code, rec.Body.String())
	}

	// Store should have 0 passkeys and requirePasskey should be auto-disabled
	store.Read(func(cfg *models.AppConfig) {
		if len(cfg.Server.Passkeys) != 0 {
			t.Fatalf("expected 0 passkeys, got %d", len(cfg.Server.Passkeys))
		}
		if cfg.Server.RequirePasskey {
			t.Fatalf("expected RequirePasskey to be auto-disabled after deleting all passkeys")
		}
	})
}
