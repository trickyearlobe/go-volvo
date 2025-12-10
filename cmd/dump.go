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

	"github.com/spf13/cobra"
)

var vinNumber string

var dumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "Dump vehicle data from the Volvo API",
	Long:  `Dump vehicle data by calling multiple Volvo API endpoints for a specific VIN.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if vinNumber == "" {
			return fmt.Errorf("--vin flag is required")
		}

		endpoints := getDumpEndpoints()
		consolidated := make(map[string]interface{})

		for key, endpoint := range endpoints {
			url := joinUrl(volvoApiBaseUrl, fmt.Sprintf(endpoint, vinNumber))
			body, statusCode, err := makeVolvoRequest(url, "GET", "")
			if err == nil && statusCode == 200 {
				var dataString map[string]interface{}
				err := json.Unmarshal(body, &dataString)
				if err != nil {
					fmt.Printf("Error: %v\n", err)
				} else {
					consolidated[key] = dataString["data"]
				}
			} else {
				consolidated[key] = fmt.Sprintf("HTTP error %d occured fetching %s", statusCode, url)
			}
		}

		output, err := json.MarshalIndent(consolidated, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal result: %w", err)
		} else {
			fmt.Println(string(output))
		}
		return nil
	},
}

func getDumpEndpoints() map[string]string {
	return map[string]string{
		"commands":              "/connected-vehicle/v2/vehicles/%s/commands",
		"command-accessibility": "/connected-vehicle/v2/vehicles/%s/command-accessibility",
		"engine":                "/connected-vehicle/v2/vehicles/%s/engine",
		"diagnostics":           "/connected-vehicle/v2/vehicles/%s/diagnostics",
		"brakes":                "/connected-vehicle/v2/vehicles/%s/brakes",
		"windows":               "/connected-vehicle/v2/vehicles/%s/windows",
		"doors":                 "/connected-vehicle/v2/vehicles/%s/doors",
		"engine-status":         "/connected-vehicle/v2/vehicles/%s/engine-status",
		"fuel":                  "/connected-vehicle/v2/vehicles/%s/fuel",
		"odometer":              "/connected-vehicle/v2/vehicles/%s/odometer",
		"statistics":            "/connected-vehicle/v2/vehicles/%s/statistics",
		"tyres":                 "/connected-vehicle/v2/vehicles/%s/tyres",
		"vehicle":               "/connected-vehicle/v2/vehicles/%s",
		"warnings":              "/connected-vehicle/v2/vehicles/%s/warnings",
	}
}

func init() {
	rootCmd.AddCommand(dumpCmd)
	dumpCmd.Flags().StringVarP(&vinNumber, "vin", "v", "", "Vehicle Identification Number")
	dumpCmd.MarkFlagRequired("vin")
}
