package server_test

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
	"uuid"

	"authentikManager/internal/audit"
	"authentikManager/internal/authentik"
	"authentikManager/internal/authority"
	"authentikManager/internal/pki"
)

// addStaffCA adds the CA named "staff-ca", issuing for members of staff only, to
// env and returns its record and certificate PEM.
func addStaffCA(t *testing.T, env *certEnv) (authority.Authority, []byte) {
	t.Helper()
	certPEM, keyPEM := newTestCAPEM(t, "Staff CA")
	settings := settingsFor(suffixOptions)
	settings.UserCNSuffix = "@staff.example.com"
	settings.AllowedGroups = []string{"staff"}
	return env.addCA(t, "staff-ca", settings, certPEM, keyPEM), certPEM
}

// staffAccountUsers is ownAccountUsers with admin a member of staff.
func staffAccountUsers() *fakeUsers {
	users := ownAccountUsers()
	users.listed[0].Groups = []authentik.UserGroup{{PK: "pk-staff", Name: "staff"}}
	return users
}

func TestAuthorities_issueWithNamedCA(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, staffAccountUsers())
	staff, certPEM := addStaffCA(t, env)

	out := issue(t, env, strings.Replace(csrBody(t), "{", `{"ca_id":"`+staff.ID.String()+`",`, 1))
	if c := out.Certificate; c.CAID != staff.ID || c.Subject != "CN=admin@staff.example.com" {
		t.Errorf("certificate = %+v, want one of staff-ca with its suffix", c)
	}
	if out.ChainPEM != string(certPEM) {
		t.Errorf("chain = %q, want the chain of staff-ca", out.ChainPEM)
	}
	block, _ := pem.Decode([]byte(out.CertificatePEM))
	if block == nil {
		t.Fatal("no certificate PEM")
	}
	if e := env.log.recorded[0]; e.Action != audit.ActionCertificateIssued || e.Details["ca_id"] != staff.ID.String() {
		t.Errorf("audit entry = %+v, want the CA recorded", e)
	}

	// Without a name, the default CA signs.
	if c := issue(t, env, `{"format":"pem"}`).Certificate; c.CAID != env.caID {
		t.Errorf("certificate = %+v, want one of the default CA", c)
	}
}

func TestAuthorities_issueRefused(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// ca is the requested CA's id; empty for staff-ca's.
		ca       string
		disable  bool
		expected int
		message  string
	}{
		{name: "malformed id", ca: "staff-ca", expected: http.StatusBadRequest, message: `"ca_id"`},
		{name: "unknown ca", ca: uuid.New().String(), expected: http.StatusBadRequest, message: `"ca_id"`},
		{name: "disabled ca", disable: true, expected: http.StatusBadRequest, message: `"ca_id"`},
		{name: "ca of other groups", expected: http.StatusForbidden, message: "does not issue"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := newCertServer(t, ownAccountUsers())
			staff, _ := addStaffCA(t, env)
			if tt.disable {
				if _, err := env.authorities.UpdateAuthority(t.Context(), staff.ID, staff.Settings, true); err != nil {
					t.Fatal(err)
				}
				env.reload(t)
			}
			ca := tt.ca
			if ca == "" {
				ca = staff.ID.String()
			}
			rec := do(t, env.srv, http.MethodPost, "/api/certificates/mine", `{"format":"pem","ca_id":"`+ca+`"}`)
			if rec.Code != tt.expected || !strings.Contains(rec.Body.String(), tt.message) {
				t.Errorf("issue = %d %s, want %d mentioning %s", rec.Code, rec.Body, tt.expected, tt.message)
			}
			if len(env.certs.certs) != 0 {
				t.Errorf("stored %d certificates, want none", len(env.certs.certs))
			}
		})
	}
}

func TestAuthorities_issueFallsBackFromDefault(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, staffAccountUsers())
	staff, _ := addStaffCA(t, env)
	main := env.authorities.list[0]
	main.AllowedGroups = []string{"admins-only"}
	if _, err := env.authorities.UpdateAuthority(t.Context(), main.ID, main.Settings, false); err != nil {
		t.Fatal(err)
	}
	env.reload(t)

	if c := issue(t, env, `{"format":"pem"}`).Certificate; c.CAID != staff.ID {
		t.Errorf("certificate = %+v, want one of staff-ca, the only CA for admin", c)
	}

	env.authorities.list[1].AllowedGroups = []string{"nobody"}
	env.reload(t)
	rec := do(t, env.srv, http.MethodPost, "/api/certificates/mine", `{"format":"pem"}`)
	if rec.Code != http.StatusForbidden {
		t.Errorf("issue without a usable CA = %d %s, want 403", rec.Code, rec.Body)
	}
}

func TestAuthorities_listUsable(t *testing.T) {
	t.Parallel()
	env := newCertServerWithOptions(t, suffixOptions, staffAccountUsers())
	addStaffCA(t, env)

	rec := do(t, env.srv, http.MethodGet, "/api/certificates/mine/authorities", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Authorities []struct {
			Name     string `json:"name"`
			Default  bool   `json:"default"`
			CNSuffix string `json:"cn_suffix"`
		} `json:"authorities"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Authorities) != 2 ||
		out.Authorities[0].Name != "main" || !out.Authorities[0].Default || out.Authorities[0].CNSuffix != "@example.com" ||
		out.Authorities[1].Name != "staff-ca" || out.Authorities[1].Default || out.Authorities[1].CNSuffix != "@staff.example.com" {
		t.Errorf("authorities = %+v, want main as default, then staff-ca", out.Authorities)
	}

	// Service accounts see their own suffix.
	svcEnv := newCertServerWithOptions(t, suffixOptions, &fakeUsers{user: serviceAccount("staff")}, "admins")
	rec = do(t, svcEnv.srv, http.MethodGet, "/api/service-accounts/5/certificate-authorities", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"cn_suffix":"@svc.example.com"`) {
		t.Errorf("service account list = %d %s, want the service account suffix", rec.Code, rec.Body)
	}
}

func TestAuthorities_crlPerCA(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, staffAccountUsers())
	staff, _ := addStaffCA(t, env)

	c := issue(t, env, `{"format":"pem","ca_id":"`+staff.ID.String()+`"}`).Certificate
	if _, err := env.certs.RevokeCertificate(t.Context(), c.Serial, "admin"); err != nil {
		t.Fatal(err)
	}

	staffEntry, _ := env.cas.ByID(staff.ID)
	rec := do(t, env.srv, http.MethodGet, "/pki/"+staff.ID.String()+"/crl", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("staff-ca crl = %d %s", rec.Code, rec.Body)
	}
	if crl := parseCRL(t, rec.Body.Bytes(), staffEntry.CA); len(crl) != 1 || crl[0] != c.Serial {
		t.Errorf("staff-ca revoked = %v, want [%s]", crl, c.Serial)
	}
	rec = do(t, env.srv, http.MethodGet, "/pki/crl", "")
	if crl := parseCRL(t, rec.Body.Bytes(), env.ca); len(crl) != 0 {
		t.Errorf("default CA revoked = %v, want none", crl)
	}
	rec = do(t, env.srv, http.MethodGet, "/pki/"+env.caID.String()+"/crl", "")
	if crl := parseCRL(t, rec.Body.Bytes(), env.ca); rec.Code != http.StatusOK || len(crl) != 0 {
		t.Errorf("main crl = %d, revoked %v, want none", rec.Code, crl)
	}

	rec = do(t, env.srv, http.MethodGet, "/pki/"+staff.ID.String()+"/ca.pem", "")
	if block, _ := pem.Decode(rec.Body.Bytes()); rec.Code != http.StatusOK || block == nil ||
		!slices.Equal(block.Bytes, staffEntry.CA.Certificate().Raw) {
		t.Errorf("staff-ca ca.pem = %d %s", rec.Code, rec.Body)
	}
	unknown := uuid.New().String()
	for _, target := range []string{
		"/pki/" + unknown + "/crl", "/pki/" + unknown + "/crl.pem", "/pki/" + unknown + "/ca.pem",
		// CAs are found by their id only.
		"/pki/staff-ca/crl", "/pki/staff-ca/ca.pem",
	} {
		if rec := do(t, env.srv, http.MethodGet, target, ""); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", target, rec.Code)
		}
	}
}

// parseCRL parses a DER CRL, checks that ca signed it and returns its serials.
func parseCRL(t *testing.T, der []byte, ca *pki.CA) []string {
	t.Helper()
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(ca.Certificate()); err != nil {
		t.Fatal(err)
	}
	serials := []string{}
	for _, e := range crl.RevokedCertificateEntries {
		serials = append(serials, pki.SerialText(e.SerialNumber))
	}
	return serials
}

func TestAuthorities_importFromAnyCA(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, importUsers(), "admins")
	staff, _ := addStaffCA(t, env)
	staffEntry, _ := env.cas.ByID(staff.ID)
	// Disabled CAs are imported from too, so their certificates can be revoked.
	if _, err := env.authorities.UpdateAuthority(t.Context(), staff.ID, staff.Settings, true); err != nil {
		t.Fatal(err)
	}
	env.reload(t)

	annPEM, _ := signPEM(t, staffEntry.CA, pki.Subject{Username: "ann"}, time.Now())
	rec := do(t, env.srv, http.MethodPost, "/api/certificates/import", importBody(t, annPEM+string(staffEntry.CA.ChainPEM())))
	if rec.Code != http.StatusOK {
		t.Fatalf("import = %d %s", rec.Code, rec.Body)
	}
	var out importResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 1 || out.Results[0].Certificate == nil || out.Results[0].Certificate.CAID != staff.ID {
		t.Errorf("results = %+v, want ann's certificate of staff-ca, without the CA", out.Results)
	}
}

// createBody returns the body of a request creating the CA name of certPEM and keyPEM.
func createBody(t *testing.T, name string, certPEM, keyPEM []byte, extra map[string]any) string {
	t.Helper()
	body := map[string]any{"name": name, "certificate_pem": string(certPEM), "key_pem": string(keyPEM)}
	maps.Copy(body, extra)
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type authorityResponse struct {
	authority.Authority
	Subject     string `json:"subject"`
	Fingerprint string `json:"fingerprint_sha256"`
}

func TestAuthorities_adminOnly(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, ownAccountUsers(), "helpdesk")
	certPEM, keyPEM := newTestCAPEM(t, "New CA")
	for _, req := range []struct{ method, target, body string }{
		{http.MethodPost, "/api/certificate-authorities", createBody(t, "new", certPEM, keyPEM, nil)},
		{http.MethodPut, "/api/certificate-authorities/" + env.caID.String(), `{}`},
		{http.MethodPost, "/api/certificate-authorities/" + env.caID.String() + "/default", ""},
	} {
		if rec := do(t, env.srv, req.method, req.target, req.body); rec.Code != http.StatusForbidden {
			t.Errorf("%s %s = %d, want 403", req.method, req.target, rec.Code)
		}
	}
	if len(env.authorities.list) != 1 {
		t.Errorf("stored %d CAs, want only main", len(env.authorities.list))
	}
}

func TestAuthorities_create(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, staffAccountUsers(), "admins")
	certPEM, keyPEM := newTestCAPEM(t, "New CA")

	rec := do(t, env.srv, http.MethodPost, "/api/certificate-authorities", createBody(t, "new-ca", certPEM, keyPEM, map[string]any{
		"description": " For staff ", "validity_days": 30, "allowed_groups": []string{"staff", " staff", ""},
	}))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var created authorityResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	checkCreated(t, created)
	checkKeyKept(t, env, rec.Body.String())
	if e := env.log.recorded[0]; e.Action != audit.ActionAuthorityCreated || e.Target != created.ID.String() || e.Details["name"] != "new-ca" {
		t.Errorf("audit entry = %+v, want the creation", e)
	}
	// The new CA issues certificates right away.
	if c := issue(t, env, `{"format":"pem","ca_id":"`+created.ID.String()+`"}`).Certificate; c.CAID != created.ID {
		t.Errorf("certificate = %+v, want one of new-ca", c)
	}

	rec = do(t, env.srv, http.MethodPost, "/api/certificate-authorities", createBody(t, "again", certPEM, keyPEM, nil))
	if rec.Code != http.StatusConflict {
		t.Errorf("create with the same certificate = %d %s, want 409", rec.Code, rec.Body)
	}
}

// checkCreated checks the CA TestAuthorities_create created.
func checkCreated(t *testing.T, created authorityResponse) {
	t.Helper()
	if created.Name != "new-ca" || created.Default || created.Description != "For staff" || created.ValidityDays != 30 ||
		created.CRLValidityDays != authority.DefaultCRLValidityDays || !slices.Equal(created.AllowedGroups, []string{"staff"}) ||
		created.Subject != "CN=New CA" || len(created.Fingerprint) != 64 || created.CreatedBy != "admin" {
		t.Errorf("created = %+v", created)
	}
}

// checkKeyKept checks that the response body does not expose the key of the
// CA created last and that it is stored encrypted.
func checkKeyKept(t *testing.T, env *certEnv, body string) {
	t.Helper()
	if strings.Contains(body, "PRIVATE KEY") || strings.Contains(body, "key_ciphertext") {
		t.Errorf("response %s exposes the key", body)
	}
	if strings.Contains(string(env.authorities.list[len(env.authorities.list)-1].KeyCiphertext), "PRIVATE KEY") {
		t.Error("the key is stored unencrypted")
	}
}

func TestAuthorities_createInvalid(t *testing.T) {
	t.Parallel()
	certPEM, keyPEM := newTestCAPEM(t, "New CA")
	_, otherKey := newTestCAPEM(t, "Other CA")
	tests := []struct {
		name     string
		caName   string
		certPEM  []byte
		keyPEM   []byte
		settings map[string]any
		message  string
	}{
		{name: "invalid name", caName: "new\x07", certPEM: certPEM, keyPEM: keyPEM, message: `"name"`},
		{name: "mismatched key", caName: "new", certPEM: certPEM, keyPEM: otherKey, message: "does not match"},
		{name: "no certificate", caName: "new", keyPEM: keyPEM, message: "no CERTIFICATE block"},
		{
			name: "relative crl url", caName: "new", certPEM: certPEM, keyPEM: keyPEM,
			settings: map[string]any{"crl_url": "/pki/new/crl"}, message: "CRL URL",
		},
		{
			name: "validity too long", caName: "new", certPEM: certPEM, keyPEM: keyPEM,
			settings: map[string]any{"validity_days": 4000}, message: "validity",
		},
		{
			name: "control character in suffix", caName: "new", certPEM: certPEM, keyPEM: keyPEM,
			settings: map[string]any{"user_cn_suffix": "@a\x07"}, message: "control characters",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := newCertServer(t, ownAccountUsers(), "admins")
			body := createBody(t, tt.caName, tt.certPEM, tt.keyPEM, tt.settings)
			rec := do(t, env.srv, http.MethodPost, "/api/certificate-authorities", body)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tt.message) {
				t.Errorf("create = %d %s, want 400 mentioning %s", rec.Code, rec.Body, tt.message)
			}
			if len(env.authorities.list) != 1 {
				t.Errorf("stored %d CAs, want only main", len(env.authorities.list))
			}
		})
	}
}

func TestAuthorities_update(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, staffAccountUsers(), "admins")
	staff, _ := addStaffCA(t, env)
	target := "/api/certificate-authorities/" + staff.ID.String()

	rec := do(t, env.srv, http.MethodPut, target, `{"validity_days":10,"user_cn_suffix":"@new.example.com","allowed_groups":["staff"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("update = %d %s", rec.Code, rec.Body)
	}
	if c := issue(t, env, `{"format":"pem","ca_id":"`+staff.ID.String()+`"}`).Certificate; c.Subject != "CN=admin@new.example.com" {
		t.Errorf("certificate = %+v, want the new suffix", c)
	}
	e := env.log.recorded[0]
	if e.Action != audit.ActionAuthorityUpdated || e.Details["user_cn_suffix"] != "@staff.example.com → @new.example.com" {
		t.Errorf("audit entry = %+v, want the changed suffix", e)
	}

	if rec := do(t, env.srv, http.MethodPut, target, `{"disabled":true}`); rec.Code != http.StatusOK {
		t.Fatalf("disable = %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, env.srv, http.MethodPost, "/api/certificates/mine", `{"format":"pem","ca_id":"`+staff.ID.String()+`"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("issue with the disabled CA = %d, want 400", rec.Code)
	}

	mainTarget := "/api/certificate-authorities/" + env.caID.String()
	if rec := do(t, env.srv, http.MethodPut, mainTarget, `{"disabled":true}`); rec.Code != http.StatusConflict {
		t.Errorf("disable the default CA = %d %s, want 409", rec.Code, rec.Body)
	}
	if rec := do(t, env.srv, http.MethodPut, "/api/certificate-authorities/"+uuid.New().String(), `{}`); rec.Code != http.StatusNotFound {
		t.Errorf("update unknown CA = %d, want 404", rec.Code)
	}
	if rec := do(t, env.srv, http.MethodPut, "/api/certificate-authorities/1", `{}`); rec.Code != http.StatusBadRequest {
		t.Errorf("update with an invalid id = %d, want 400", rec.Code)
	}
	if rec := do(t, env.srv, http.MethodPut, target, `{"validity_days":-1}`); rec.Code != http.StatusBadRequest {
		t.Errorf("update with invalid settings = %d, want 400", rec.Code)
	}
}

func TestAuthorities_setDefault(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, staffAccountUsers(), "admins")
	env.authorities.list[0].Legacy = true
	staff, _ := addStaffCA(t, env)

	rec := do(t, env.srv, http.MethodPost, "/api/certificate-authorities/"+staff.ID.String()+"/default", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"default":true`) {
		t.Fatalf("set default = %d %s", rec.Code, rec.Body)
	}
	if c := issue(t, env, `{"format":"pem"}`).Certificate; c.CAID != staff.ID {
		t.Errorf("certificate = %+v, want one of the new default CA", c)
	}
	// The unnamed URLs keep serving the legacy CA, whose certificates may embed them.
	rec = do(t, env.srv, http.MethodGet, "/pki/ca.pem", "")
	if block, _ := pem.Decode(rec.Body.Bytes()); block == nil || !slices.Equal(block.Bytes, env.caCert.Raw) {
		t.Errorf("ca.pem = %s, want the legacy CA", rec.Body)
	}
	if e := env.log.recorded[0]; e.Action != audit.ActionAuthorityDefaultChanged || e.Target != staff.ID.String() {
		t.Errorf("audit entry = %+v, want the default change", e)
	}
}

func TestAuthorities_list(t *testing.T) {
	t.Parallel()
	// Users who are no access administrators may view the CAs too.
	env := newCertServer(t, ownAccountUsers(), "helpdesk")
	addStaffCA(t, env)

	rec := do(t, env.srv, http.MethodGet, "/api/certificate-authorities", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Authorities []authorityResponse `json:"authorities"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Authorities) != 2 || out.Authorities[0].Name != "main" || !out.Authorities[0].Default ||
		out.Authorities[1].Name != "staff-ca" || out.Authorities[1].Subject != "CN=Staff CA" {
		t.Errorf("authorities = %+v", out.Authorities)
	}
	if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Errorf("list %s exposes a key", rec.Body)
	}
}

func TestServiceAPI_issueWithNamedCA(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, &fakeUsers{user: serviceAccount("staff")})
	staff, _ := addStaffCA(t, env)
	_, key := env.keys.add(5, nil)

	var body map[string]string
	if err := json.Unmarshal([]byte(csrBody(t)), &body); err != nil {
		t.Fatal(err)
	}
	body["ca_id"] = staff.ID.String()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	rec := callServiceAPI(t, env.srv, http.MethodPost, "/service-api/v1/certificates", "Bearer "+key, string(b))
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue = %d %s", rec.Code, rec.Body)
	}
	var out issueResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Certificate.CAID != staff.ID {
		t.Errorf("certificate = %+v, want one of staff-ca", out.Certificate)
	}

	rec = callServiceAPI(t, env.srv, http.MethodGet, "/service-api/v1/certificate-authorities", "Bearer "+key, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"id":"`+staff.ID.String()+`"`) {
		t.Errorf("list = %d %s, want staff-ca", rec.Code, rec.Body)
	}
}
