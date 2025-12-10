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
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	vccApiKey string
	token     string
)

var credentialsCmd = &cobra.Command{
	Use:   "credentials",
	Short: "Set and save Volvo API credentials",
	Long:  `Set and save your Volvo API credentials to the config file. Credentials are stored in ~/.go-volvo.yaml by default. We need both a VCC API key and a 'test' token from the developer portal.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if vccApiKey != "" {
			viper.Set("vccApiKey", vccApiKey)
		}
		if token != "" {
			viper.Set("token", token)
		}

		configFile := viper.ConfigFileUsed()
		if configFile == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("failed to get home directory: %w", err)
			}
			configFile = filepath.Join(home, ".go-volvo.yaml")
			viper.SetConfigFile(configFile)
		}

		err := viper.WriteConfig()
		if err != nil {
			// Config file might not exist yet, try SafeWriteConfig
			err = viper.SafeWriteConfig()
			if err != nil {
				return fmt.Errorf("failed to save credentials: %w", err)
			}
		}

		fmt.Println("Credentials saved to", configFile)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(credentialsCmd)
	credentialsCmd.Flags().StringVarP(&vccApiKey, "vcc-api-key", "k", "", "VCC API key from developer portal")
	credentialsCmd.Flags().StringVarP(&token, "token", "t", "", "Volvo API 'test'token from developer portal")
}
