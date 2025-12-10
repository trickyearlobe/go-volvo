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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/viper"
)

func TestRawCommandExists(t *testing.T) {
	found := false
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "raw" {
			found = true
			break
		}
	}
	if !found {
		t.Error("raw command not found in root command")
	}
}

func TestRawVerbSubcommandsExist(t *testing.T) {
	expectedVerbs := []string{"get", "post", "put", "patch", "delete", "head", "options"}

	for _, verb := range expectedVerbs {
		found := false
		for _, cmd := range rawCmd.Commands() {
			if cmd.Name() == verb {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s subcommand not found in raw command", verb)
		}
	}
}

func TestMakeVolvoRequest(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify headers
		if r.Header.Get("VCC-Api-Key") != "test-api-key" {
			t.Errorf("expected VCC-Api-Key header 'test-api-key', got '%s'", r.Header.Get("VCC-Api-Key"))
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("expected Accept header 'application/json', got '%s'", r.Header.Get("Accept"))
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	// Set up viper with test credentials
	viper.Reset()
	viper.Set("vccApiKey", "test-api-key")
	viper.Set("token", "test-token")

	// Test the request function without data
	body, statusCode, err := makeVolvoRequest(server.URL, "GET", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if statusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", statusCode)
	}
	if string(body) != `{"status": "ok"}` {
		t.Errorf("unexpected body: %s", string(body))
	}
}

func TestMakeVolvoRequestWithData(t *testing.T) {
	testData := `{"name": "test"}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Content-Type header is set when data is provided
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type header 'application/json', got '%s'", r.Header.Get("Content-Type"))
		}

		// Verify request body
		body, _ := io.ReadAll(r.Body)
		if string(body) != testData {
			t.Errorf("expected body '%s', got '%s'", testData, string(body))
		}

		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id": 1}`))
	}))
	defer server.Close()

	viper.Reset()
	viper.Set("vccApiKey", "test-api-key")
	viper.Set("token", "test-token")

	body, statusCode, err := makeVolvoRequest(server.URL, "POST", testData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if statusCode != http.StatusCreated {
		t.Errorf("expected status 201, got %d", statusCode)
	}
	if string(body) != `{"id": 1}` {
		t.Errorf("unexpected body: %s", string(body))
	}
}

func TestMakeVolvoRequestMissingApiKey(t *testing.T) {
	viper.Reset()
	// Don't set vccApiKey

	_, _, err := makeVolvoRequest("http://example.com/test", "GET", "")
	if err == nil {
		t.Error("expected error for missing API key")
	}
}

func TestMakeVolvoRequestLowercaseMethod(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify method is uppercase
		if r.Method != "GET" {
			t.Errorf("expected method 'GET', got '%s'", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	viper.Reset()
	viper.Set("vccApiKey", "test-api-key")
	viper.Set("token", "test-token")

	// Pass lowercase method
	_, _, err := makeVolvoRequest(server.URL, "get", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestJoinUrl(t *testing.T) {
	tests := []struct {
		base     string
		path     string
		expected string
	}{
		{"https://api.example.com", "/endpoint", "https://api.example.com/endpoint"},
		{"https://api.example.com/", "/endpoint", "https://api.example.com/endpoint"},
		{"https://api.example.com", "endpoint", "https://api.example.com/endpoint"},
		{"https://api.example.com/", "endpoint", "https://api.example.com/endpoint"},
	}

	for _, tt := range tests {
		result := joinUrl(tt.base, tt.path)
		if result != tt.expected {
			t.Errorf("joinUrl(%q, %q) = %q, expected %q", tt.base, tt.path, result, tt.expected)
		}
	}
}
