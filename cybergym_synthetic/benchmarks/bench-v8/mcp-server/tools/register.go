package tools

import (
	"github.com/exploitbench/bench-v8/mcp-server/grader"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// RegisterAll registers all MCP tools on the server.
func RegisterAll(server *mcp.Server, cfg Config) {
	RegisterSetup(server, cfg)
	RegisterExec(server)
	RegisterListDirectory(server)
	RegisterReadFile(server)
	RegisterWriteFile(server)

	// Build the composite grader with all sub-graders.
	// PrimitiveGrader now covers exploit capabilities (pc_control, ace) too,
	// via the d8 grader patch's signal handler (pc_control) and per-round
	// prctl(PR_SET_NAME) nonce challenge (ace).
	composite := &grader.CompositeGrader{
		SubGraders: []grader.SubGrader{
			&grader.CoverageGrader{},
			&grader.DiffGrader{Rounds: 3},
			&grader.PrimitiveGrader{Rounds: 3},
		},
	}

	RegisterGrade(server, cfg, composite)
}
