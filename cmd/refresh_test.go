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
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRefreshCommandExists(t *testing.T) {
	found := false
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "refresh" {
			found = true
			break
		}
	}
	if !found {
		t.Error("refresh command not found in root command")
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

