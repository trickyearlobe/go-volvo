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
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

func TestCredentialsCommand(t *testing.T) {
	// Create a temp directory for test config
	tmpDir, err := os.MkdirTemp("", "go-volvo-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, ".go-volvo.yaml")

	// Reset viper for test
	viper.Reset()
	viper.SetConfigFile(configPath)

	// Test setting credentials
	testUsername := "testuser@example.com"
	testVccApiKey := "test-api-key-12345"

	viper.Set("username", testUsername)
	viper.Set("vccApiKey", testVccApiKey)

	err = viper.WriteConfig()
	if err != nil {
		err = viper.SafeWriteConfig()
		if err != nil {
			t.Fatalf("failed to write config: %v", err)
		}
	}

	// Read back and verify
	viper.Reset()
	viper.SetConfigFile(configPath)
	err = viper.ReadInConfig()
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}

	if viper.GetString("username") != testUsername {
		t.Errorf("expected username %s, got %s", testUsername, viper.GetString("username"))
	}
	if viper.GetString("vccApiKey") != testVccApiKey {
		t.Errorf("expected vccApiKey %s, got %s", testVccApiKey, viper.GetString("vccApiKey"))
	}
}

func TestCredentialsCommandExists(t *testing.T) {
	// Verify the credentials command is registered
	found := false
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "credentials" {
			found = true
			break
		}
	}
	if !found {
		t.Error("credentials command not found in root command")
	}
}
