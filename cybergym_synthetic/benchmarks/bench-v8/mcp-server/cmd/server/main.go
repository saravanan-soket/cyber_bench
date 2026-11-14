package main

import (
	"context"
	"log"
	"os"

	"github.com/exploitbench/bench-v8/mcp-server/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	serverName    = "bench-v8"
	serverVersion = "0.1.0"
)

func main() {
	// Fix PATH to root-owned dirs only. The container's inherited PATH
	// prepends /rlenv/source/depot_tools (agent-writable), which would
	// let the agent shadow binaries LookPath'd by grader subprocesses.
	// Agent-facing exec tool re-adds depot_tools for its own children.
	os.Setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")

	cfg := tools.ConfigFromEnv()

	// Fast-fail if any isolation invariant is missing.  Checking now beats
	// a silent downgrade that only shows up as false-positive capabilities
	// deep in a grade run.
	if err := preflight(cfg); err != nil {
		log.Fatalf("preflight failed: %v", err)
	}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    serverName,
		Version: serverVersion,
	}, nil)

	tools.RegisterAll(server, cfg)

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}

// init runs the privilege transition from container-root → agent-UID +
// narrow caps.  Runs BEFORE main() and BEFORE any user code that might
// spawn additional goroutines, so syscall.Setresuid's AllThreadsSyscall
// broadcast has minimal thread state to synchronize.
func init() {
	downgradeFromRoot()
}
