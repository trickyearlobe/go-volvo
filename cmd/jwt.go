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
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var jwtCmd = &cobra.Command{
	Use:   "jwt",
	Short: "Decode the Volvo API JWT access token",
	Long:  `Decode and display the header and payload of the stored Volvo API JWT access token.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		token := viper.GetString("token")
		if token == "" {
			return fmt.Errorf("no access token found. Run 'go-volvo login' or configure a test token first")
		}

		headerBytes, payloadBytes, err := decodeJwtToken(token)
		if err != nil {
			return fmt.Errorf("failed to decode access token: %w", err)
		}

		var headerJson interface{}
		if err := json.Unmarshal(headerBytes, &headerJson); err != nil {
			return fmt.Errorf("failed to parse header: %w", err)
		}

		var payloadJson interface{}
		if err := json.Unmarshal(payloadBytes, &payloadJson); err != nil {
			return fmt.Errorf("failed to parse payload: %w", err)
		}

		headerPretty, err := json.MarshalIndent(headerJson, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to format header: %w", err)
		}

		payloadPretty, err := json.MarshalIndent(payloadJson, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to format payload: %w", err)
		}

		fmt.Println("Header:")
		fmt.Println(string(headerPretty))
		fmt.Println("\nPayload:")
		fmt.Println(string(payloadPretty))

		return nil
	},
}

func decodeJwtToken(token string) ([]byte, []byte, error) {
	parts := splitToken(token)
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("invalid JWT format: expected 3 parts separated by dots, got %d", len(parts))
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode header: %w", err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	return headerBytes, payloadBytes, nil
}

func splitToken(token string) []string {
	var parts []string
	var current strings.Builder
	for _, char := range token {
		if char == '.' {
			parts = append(parts, current.String())
			current.Reset()
		} else {
			current.WriteRune(char)
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return parts
}

func init() {
	rootCmd.AddCommand(jwtCmd)
}
