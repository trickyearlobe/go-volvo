/*
Copyright © 2025 Richard Nixon <richard.nixon@btinternet.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestLoginCommandExists(t *testing.T) {
	found := false
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "login" {
			found = true
			break
		}
	}
	if !found {
		t.Error("login command not found in root command")
	}
}

func TestBuildAuthUrl(t *testing.T) {
	clientId := "test-client-id"
	redirectUri := "http://localhost:8089/callback"
	codeChallenge := "test-code-challenge"

	authUrl := buildAuthUrl(clientId, redirectUri, codeChallenge)

	parsed, err := url.Parse(authUrl)
	if err != nil {
		t.Fatalf("failed to parse auth URL: %v", err)
	}

	if parsed.Host != "volvoid.eu.volvocars.com" {
		t.Errorf("unexpected host: %s", parsed.Host)
	}

	query := parsed.Query()
	if query.Get("client_id") != clientId {
		t.Errorf("expected client_id %s, got %s", clientId, query.Get("client_id"))
	}
	if query.Get("redirect_uri") != redirectUri {
		t.Errorf("expected redirect_uri %s, got %s", redirectUri, query.Get("redirect_uri"))
	}
	if query.Get("response_type") != "code" {
		t.Errorf("expected response_type 'code', got %s", query.Get("response_type"))
	}
	if query.Get("code_challenge") != codeChallenge {
		t.Errorf("expected code_challenge %s, got %s", codeChallenge, query.Get("code_challenge"))
	}
	if query.Get("code_challenge_method") != "S256" {
		t.Errorf("expected code_challenge_method 'S256', got %s", query.Get("code_challenge_method"))
	}
}

func TestExchangeCodeForToken(t *testing.T) {
	// Mock token server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}

		r.ParseForm()
		if r.Form.Get("grant_type") != "authorization_code" {
			t.Errorf("expected grant_type 'authorization_code', got %s", r.Form.Get("grant_type"))
		}
		if r.Form.Get("code") != "test-auth-code" {
			t.Errorf("expected code 'test-auth-code', got %s", r.Form.Get("code"))
		}
		if r.Form.Get("code_verifier") != "test-code-verifier" {
			t.Errorf("expected code_verifier 'test-code-verifier', got %s", r.Form.Get("code_verifier"))
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"access_token": "test-access-token",
			"refresh_token": "test-refresh-token",
			"expires_in": 1800,
			"token_type": "Bearer"
		}`))
	}))
	defer server.Close()

	tokens, err := exchangeCodeForToken(server.URL, "test-auth-code", "test-client-id", "test-client-secret", "http://localhost:8089/callback", "test-code-verifier")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tokens.AccessToken != "test-access-token" {
		t.Errorf("expected access_token 'test-access-token', got %s", tokens.AccessToken)
	}
	if tokens.RefreshToken != "test-refresh-token" {
		t.Errorf("expected refresh_token 'test-refresh-token', got %s", tokens.RefreshToken)
	}
}

func TestRefreshAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("grant_type") != "refresh_token" {
			t.Errorf("expected grant_type 'refresh_token', got %s", r.Form.Get("grant_type"))
		}
		if r.Form.Get("refresh_token") != "test-refresh-token" {
			t.Errorf("expected refresh_token 'test-refresh-token', got %s", r.Form.Get("refresh_token"))
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"access_token": "new-access-token",
			"refresh_token": "new-refresh-token",
			"expires_in": 1800,
			"token_type": "Bearer"
		}`))
	}))
	defer server.Close()

	tokens, err := refreshAccessToken(server.URL, "test-refresh-token", "test-client-id", "test-client-secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tokens.AccessToken != "new-access-token" {
		t.Errorf("expected access_token 'new-access-token', got %s", tokens.AccessToken)
	}
}

func TestGenerateSelfSignedCert(t *testing.T) {
	certPem, keyPem, err := generateSelfSignedCert("localhost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if certPem == "" {
		t.Error("expected non-empty certificate PEM")
	}
	if keyPem == "" {
		t.Error("expected non-empty key PEM")
	}

	// Verify the cert/key can be loaded
	_, err = tls.X509KeyPair([]byte(certPem), []byte(keyPem))
	if err != nil {
		t.Errorf("generated cert/key pair is invalid: %v", err)
	}
}

func TestGenerateCodeVerifier(t *testing.T) {
	verifier, err := generateCodeVerifier()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verifier should be 43 characters (32 bytes base64url encoded)
	if len(verifier) != 43 {
		t.Errorf("expected verifier length 43, got %d", len(verifier))
	}

	// Generate another and ensure they're different
	verifier2, _ := generateCodeVerifier()
	if verifier == verifier2 {
		t.Error("expected different verifiers on each call")
	}
}

func TestGenerateCodeChallenge(t *testing.T) {
	// Known test vector: verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	// should produce challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	expectedChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	challenge := generateCodeChallenge(verifier)
	if challenge != expectedChallenge {
		t.Errorf("expected challenge %s, got %s", expectedChallenge, challenge)
	}
}

