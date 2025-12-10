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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	volvoAuthUrl       = "https://volvoid.eu.volvocars.com/as/authorization.oauth2"
	volvoTokenUrl      = "https://volvoid.eu.volvocars.com/as/token.oauth2"
	defaultCallbackUrl = "https://localhost:8089/callback" // Note: Callback URL must be HTTPS for Volvo to accept it. localhost should not be accepted
	oauthScopes        = "conve:fuel_status conve:brake_status conve:doors_status conve:trip_statistics conve:environment conve:odometer_status conve:honk_flash conve:command_accessibility conve:engine_status conve:commands conve:vehicle_relation conve:windows_status conve:navigation conve:tyre_status conve:connectivity_status conve:battery_charge_level conve:climatization_start_stop conve:engine_start_stop conve:lock openid conve:diagnostics_workshop conve:unlock conve:lock_status conve:diagnostics_engine_status conve:warnings"
)

// TokenResponse represents the OAuth token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with Volvo via OAuth",
	Long:  `Opens a browser to authenticate with your Volvo ID and stores the access token.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		clientId := viper.GetString("clientId")
		clientSecret := viper.GetString("clientSecret")
		callbackUrl := viper.GetString("callbackUrl")

		if callbackUrl == "" {
			callbackUrl = defaultCallbackUrl
		}

		if clientId == "" || clientSecret == "" {
			return fmt.Errorf("clientId and clientSecret not set. Run 'go-volvo credentials --client-id YOUR_ID --client-secret YOUR_SECRET' first")
		}

		// Parse callback URL to get port and path
		parsedUrl, err := url.Parse(callbackUrl)
		if err != nil {
			return fmt.Errorf("invalid callback URL: %w", err)
		}
		port := parsedUrl.Port()
		if port == "" {
			if parsedUrl.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		callbackPath := parsedUrl.Path
		if callbackPath == "" {
			callbackPath = "/callback"
		}
		useHttps := parsedUrl.Scheme == "https"

		// Get TLS config for HTTPS
		var tlsConfig *tls.Config
		if useHttps {
			var err error
			tlsConfig, err = getTlsConfig()
			if err != nil {
				return fmt.Errorf("failed to configure TLS: %w", err)
			}
		}

		// Generate PKCE code verifier and challenge
		codeVerifier, err := generateCodeVerifier()
		if err != nil {
			return fmt.Errorf("failed to generate PKCE code verifier: %w", err)
		}
		codeChallenge := generateCodeChallenge(codeVerifier)

		// Channel to receive the auth code
		codeChan := make(chan string, 1)
		errChan := make(chan error, 1)

		// Start local server to receive callback
		mux := http.NewServeMux()
		server := &http.Server{Addr: ":" + port, Handler: mux, TLSConfig: tlsConfig}
		mux.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
			code := r.URL.Query().Get("code")
			if code == "" {
				errChan <- fmt.Errorf("no authorization code received")
				w.Write([]byte("Error: No authorization code received. You can close this window."))
				return
			}
			codeChan <- code
			w.Write([]byte("Authorization successful! You can close this window and return to the terminal."))
		})

		go func() {
			var err error
			if useHttps {
				err = server.ListenAndServeTLS("", "")
			} else {
				err = server.ListenAndServe()
			}
			if err != http.ErrServerClosed {
				errChan <- err
			}
		}()

		// Open browser to auth URL
		authUrl := buildAuthUrl(clientId, callbackUrl, codeChallenge)
		fmt.Printf("Callback URL: %s\n", callbackUrl)
		fmt.Printf("Listening on port: %s\n", port)
		fmt.Println("Opening browser for Volvo authentication...")
		fmt.Printf("If browser doesn't open, visit: %s\n\n", authUrl)
		openBrowser(authUrl)

		// Wait for callback or timeout
		var authCode string
		select {
		case authCode = <-codeChan:
			fmt.Println("Authorization code received!")
		case err := <-errChan:
			server.Shutdown(context.Background())
			return err
		case <-time.After(5 * time.Minute):
			server.Shutdown(context.Background())
			return fmt.Errorf("timeout waiting for authorization")
		}

		server.Shutdown(context.Background())

		// Exchange code for tokens
		fmt.Println("Exchanging authorization code for tokens...")
		tokens, err := exchangeCodeForToken(volvoTokenUrl, authCode, clientId, clientSecret, callbackUrl, codeVerifier)
		if err != nil {
			return fmt.Errorf("failed to exchange code for token: %w", err)
		}

		// Save tokens
		viper.Set("token", tokens.AccessToken)
		viper.Set("refreshToken", tokens.RefreshToken)
		viper.Set("tokenExpiresAt", time.Now().Add(time.Duration(tokens.ExpiresIn)*time.Second).Unix())

		if err := viper.WriteConfig(); err != nil {
			return fmt.Errorf("failed to save tokens: %w", err)
		}

		fmt.Println("Login successful! Tokens saved to config.")
		return nil
	},
}

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
		return nil
	},
}

// generateCodeVerifier creates a random code verifier for PKCE
func generateCodeVerifier() (string, error) {
	// Generate 32 random bytes (will be 43 chars when base64url encoded)
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// generateCodeChallenge creates a code challenge from the verifier using S256 method
func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func buildAuthUrl(clientId string, redirectUri string, codeChallenge string) string {
	params := url.Values{
		"client_id":             {clientId},
		"redirect_uri":          {redirectUri},
		"response_type":         {"code"},
		"scope":                 {oauthScopes},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}
	return volvoAuthUrl + "?" + params.Encode()
}

func exchangeCodeForToken(tokenUrl string, code string, clientId string, clientSecret string, redirectUri string, codeVerifier string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectUri},
		"client_id":     {clientId},
		"client_secret": {clientSecret},
		"code_verifier": {codeVerifier},
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
		return nil, fmt.Errorf("token request failed: %s", string(body))
	}

	var tokens TokenResponse
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, err
	}

	return &tokens, nil
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

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", strings.ReplaceAll(url, "&", "^&"))
	}
	if cmd != nil {
		cmd.Start()
	}
}

func generateSelfSignedCert(hostname string) (certPem string, keyPem string, err error) {
	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"go-volvo"},
			CommonName:   hostname,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname, "localhost"},
	}

	// Create certificate
	certDer, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDer})

	// Encode private key to PEM
	keyDer, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer})

	return string(certPemBytes), string(keyPemBytes), nil
}

func getTlsConfig() (*tls.Config, error) {
	certPem := viper.GetString("tlsCert")
	keyPem := viper.GetString("tlsKey")

	// Generate self-signed cert if not configured
	if certPem == "" || keyPem == "" {
		fmt.Println("No TLS certificate configured, generating self-signed certificate...")
		callbackUrl := viper.GetString("callbackUrl")
		if callbackUrl == "" {
			callbackUrl = defaultCallbackUrl
		}
		parsedUrl, _ := url.Parse(callbackUrl)
		hostname := parsedUrl.Hostname()

		var err error
		certPem, keyPem, err = generateSelfSignedCert(hostname)
		if err != nil {
			return nil, err
		}

		// Save generated cert to config
		viper.Set("tlsCert", certPem)
		viper.Set("tlsKey", keyPem)
		if err := viper.WriteConfig(); err != nil {
			fmt.Printf("Warning: could not save generated certificate to config: %v\n", err)
		} else {
			fmt.Println("Self-signed certificate saved to config.")
		}
	}

	cert, err := tls.X509KeyPair([]byte(certPem), []byte(keyPem))
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

func init() {
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(refreshCmd)
}
