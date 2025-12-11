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
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/spf13/viper"
)

func TestJwtCommandExists(t *testing.T) {
	found := false
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "jwt" {
			found = true
			break
		}
	}
	if !found {
		t.Error("jwt command not found in root command")
	}
}

func TestDecodeJwtRefreshToken(t *testing.T) {
	// Create a test JWT refresh token
	header := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
	}
	payload := map[string]interface{}{
		"sub": "1234567890",
		"token_type": "refresh",
		"exp": 9999999999,
	}

	headerJson, _ := json.Marshal(header)
	payloadJson, _ := json.Marshal(payload)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJson)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJson)
	signature := "test-signature"

	refreshToken := headerB64 + "." + payloadB64 + "." + signature

	// Set refresh token in viper
	viper.Set("refreshToken", refreshToken)

	headerBytes, payloadBytes, err := decodeJwtToken(refreshToken)
	if err != nil {
		t.Fatalf("failed to decode token: %v", err)
	}

	var headerResult map[string]interface{}
	if err := json.Unmarshal(headerBytes, &headerResult); err != nil {
		t.Fatalf("failed to unmarshal header: %v", err)
	}

	if headerResult["alg"] != "HS256" {
		t.Errorf("expected alg 'HS256', got %v", headerResult["alg"])
	}

	var payloadResult map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payloadResult); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	if payloadResult["token_type"] != "refresh" {
		t.Errorf("expected token_type 'refresh', got %v", payloadResult["token_type"])
	}
}

func TestDecodeJwtRefreshTokenInvalidFormat(t *testing.T) {
	invalidTokens := []string{
		"not-a-jwt",
		"only-one-part",
		"two.parts",
		"",
	}

	for _, token := range invalidTokens {
		_, _, err := decodeJwtToken(token)
		if err == nil {
			t.Errorf("expected error for invalid token: %s", token)
		}
	}
}

