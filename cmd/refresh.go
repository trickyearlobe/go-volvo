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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var refreshCmd = &cobra.Command{
	Use:   "refresh",
	Short: "Refresh the access token",
	Long:  `Use the stored refresh token to get a new access token.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		clientId := viper.GetString("clientId")
		clientSecret := viper.GetString("clientSecret")
		refreshToken := viper.GetString("refreshToken")

		if clientId == "" || clientSecret == "" {
			return fmt.Errorf("clientId and clientSecret not set")
		}
		if refreshToken == "" {
			return fmt.Errorf("no refresh token found. Run 'go-volvo login' first")
		}

		tokens, err := refreshAccessToken(volvoTokenUrl, refreshToken, clientId, clientSecret)
		if err != nil {
			return fmt.Errorf("failed to refresh token: %w", err)
		}

		viper.Set("token", tokens.AccessToken)
		viper.Set("refreshToken", tokens.RefreshToken)
		viper.Set("tokenExpiresAt", time.Now().Add(time.Duration(tokens.ExpiresIn)*time.Second).Unix())

		if err := viper.WriteConfig(); err != nil {
			return fmt.Errorf("failed to save tokens: %w", err)
		}

		fmt.Println("Token refreshed successfully!")
		fmt.Printf("New access token expires in: %d seconds which is at %s\n", tokens.ExpiresIn, time.Now().Add(time.Duration(tokens.ExpiresIn)*time.Second).Format(time.RFC3339))
		return nil
	},
}

func refreshAccessToken(tokenUrl string, refreshToken string, clientId string, clientSecret string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientId},
		"client_secret": {clientSecret},
	}

	resp, err := http.PostForm(tokenUrl, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed: %s", string(body))
	}

	var tokens TokenResponse
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, err
	}

	return &tokens, nil
}

func init() {
	rootCmd.AddCommand(refreshCmd)
}
