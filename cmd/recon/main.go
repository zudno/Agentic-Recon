// Command recon is the operator CLI of Agentic-Recon: campaign lifecycle
// (init/run/triage/approve/report) over a signed scope.yaml. R0 skeleton —
// the policy engine lands in R1, the store in R2, the first modules in R3
// (README §14).
package main

import (
	"fmt"
	"os"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "-h", "--help", "help":
		usage()
	case "version":
		fmt.Println("agentic-recon", version)
	case "init":
		// R1: scaffold scope.yaml from the template, refusing to
		// overwrite, with authorization.reference mandatory.
		notImplemented("init", "R1")
	case "run":
		// R1 loads and validates the contract; R3 runs the passive
		// pipeline within it.
		notImplemented("run", "R1")
	case "triage":
		// R2/R3: manual triage over the store, no LLM required.
		notImplemented("triage", "R2")
	case "approve":
		// R4: resolve pending INTRUSIVE approval requests.
		notImplemented("approve", "R4")
	case "report":
		// R6: export the engagement report (md/json) from the store.
		notImplemented("report", "R6")
	default:
		fmt.Fprintf(os.Stderr, "recon: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func notImplemented(cmd, phase string) {
	fmt.Fprintf(os.Stderr, "recon: %q lands in %s (README §14 roadmap)\n", cmd, phase)
	os.Exit(1)
}

func usage() {
	fmt.Fprint(os.Stderr, `agentic-recon `+version+` — operator CLI

Usage: recon <command>

Commands:
  init      scaffold scope.yaml (authorization.reference mandatory)   [R1]
  run       execute a campaign within the signed scope                 [R1/R3]
  triage    manual triage over the store                              [R2/R3]
  approve   resolve pending INTRUSIVE approval requests                [R4]
  report    export the engagement report (md/json)                     [R6]
  version   print the version

Every network action goes through the policy engine (README §6).
`)
}
