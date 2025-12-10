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
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const volvoApiBaseUrl = "https://api.volvocars.com"

var rawData string

func joinUrl(base string, path string) string {
	base = strings.TrimSuffix(base, "/")
	base = strings.TrimPrefix(base, "/")
	path = strings.TrimPrefix(path, "/")
	path = strings.TrimPrefix(path, "/")
	return base + "/" + path
}

var rawCmd = &cobra.Command{
	Use:   "raw",
	Short: "Make a raw HTTP request to the Volvo API",
	Long:  `Make a raw HTTP request to the Volvo API using stored credentials. Use subcommands to specify the HTTP method.`,
}

func createVerbCmd(method string) *cobra.Command {
	return &cobra.Command{
		Use:   fmt.Sprintf("%s <endpoint>", method),
		Short: fmt.Sprintf("Make a %s request to the Volvo API", method),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			endpoint := args[0]
			url := joinUrl(volvoApiBaseUrl, endpoint)

			body, statusCode, err := makeVolvoRequest(url, method, rawData)
			if err != nil {
				fmt.Printf("Status: %d\n", statusCode)
				fmt.Println(string(body))
				return err
			}
			fmt.Println(string(body))
			return nil
		},
	}
}

func makeVolvoRequest(url string, method string, data string) ([]byte, int, error) {
	method = strings.ToUpper(method)
	apiKey := viper.GetString("vccApiKey")
	if apiKey == "" {
		return nil, 0, fmt.Errorf("vccApiKey not set. Run 'go-volvo credentials --vcc-api-key' first")
	}
	token := viper.GetString("token")
	if token == "" {
		return nil, 0, fmt.Errorf("token not set. Run 'go-volvo credentials --token' first")
	}

	var reqBody io.Reader
	if data != "" {
		reqBody = strings.NewReader(data)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("VCC-Api-Key", apiKey)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if data != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read response: %w", err)
	}

	return body, resp.StatusCode, nil
}

func init() {
	rootCmd.AddCommand(rawCmd)
	rawCmd.PersistentFlags().StringVarP(&rawData, "data", "d", "", "Request body data (JSON)")
	rawCmd.AddCommand(createVerbCmd("get"))
	rawCmd.AddCommand(createVerbCmd("post"))
	rawCmd.AddCommand(createVerbCmd("put"))
	rawCmd.AddCommand(createVerbCmd("patch"))
	rawCmd.AddCommand(createVerbCmd("delete"))
	rawCmd.AddCommand(createVerbCmd("head"))
	rawCmd.AddCommand(createVerbCmd("options"))
}
