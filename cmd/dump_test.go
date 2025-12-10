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
	"testing"
)

func TestDumpCommandExists(t *testing.T) {
	found := false
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "dump" {
			found = true
			break
		}
	}
	if !found {
		t.Error("dump command not found in root command")
	}
}

func TestDumpCommandHasVinFlag(t *testing.T) {
	flag := dumpCmd.Flags().Lookup("vin")
	if flag == nil {
		t.Error("dump command missing --vin flag")
	}
}

func TestGetDumpEndpoints(t *testing.T) {
	endpoints := getDumpEndpoints()

	expectedKeys := []string{
		"commands", "command-accessibility", "engine", "diagnostics", "brakes",
		"windows", "doors", "engine-status", "fuel", "odometer",
		"statistics", "tyres", "vehicle", "warnings",
	}

	if len(endpoints) != len(expectedKeys) {
		t.Errorf("expected %d endpoints, got %d", len(expectedKeys), len(endpoints))
	}

	for _, key := range expectedKeys {
		if _, ok := endpoints[key]; !ok {
			t.Errorf("missing endpoint key: %s", key)
		}
	}
}
