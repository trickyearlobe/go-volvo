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

	"github.com/spf13/cobra"
)

var vehiclesCmd = &cobra.Command{
	Use:   "vehicles",
	Short: "List vehicles associated with your account",
	Long:  `List all vehicles associated with your Volvo account.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		url := joinUrl(volvoApiBaseUrl, "/connected-vehicle/v2/vehicles")
		body, statusCode, err := makeVolvoRequest(url, "GET", "")
		if err != nil {
			fmt.Printf("Status: %d\n", statusCode)
			return err
		}
		fmt.Println(string(body))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(vehiclesCmd)
}

