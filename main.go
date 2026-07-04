/*
Copyright 2026 Fabricio Martinez

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

package main

import (
	"os"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/yourusername/dnsexit-webhook/solver"
)

var GroupName = "dnsexit.acme.internal"

func main() {
	if g := os.Getenv("GROUP_NAME"); g != "" {
		GroupName = g
	}

	//cmd.Run(GroupName, &solver.DNSExitSolver{})
	cmd.RunWebhookServer(GroupName, &solver.DNSExitSolver{})
}

