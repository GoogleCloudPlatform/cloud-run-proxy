// Copyright 2022 the Cloud Run Proxy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package version

import (
	"runtime"
	"runtime/debug"
)

var (
	// Name is the name of the binary.
	Name = "cloud-run-proxy"

	// Version is the main package version.
	Version = ""

	// Commit is the git sha.
	Commit = ""

	// OSArch is the operating system and architecture combination.
	OSArch = runtime.GOOS + "/" + runtime.GOARCH

	// HumanVersion is the compiled version.
	HumanVersion = func() string {
		version := Version
		if version == "" {
			version = "source"
		}

		commit := Commit
		if commit == "" {
			if info, ok := debug.ReadBuildInfo(); ok {
				for _, setting := range info.Settings {
					if setting.Key == "vcs.revision" {
						return setting.Value
					}
				}
			}
		}
		if commit == "" {
			commit = "unknown"
		}

		return Name + " " + version + " (" + commit + ", " + OSArch + ")"
	}()
)
