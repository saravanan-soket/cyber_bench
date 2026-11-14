package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type SetupInput struct{}

type SetupOutput struct {
	ID                  string            `json:"id"`
	Configs             []string          `json:"configs"`
	Prompt              string            `json:"prompt"`
	Workspace           string            `json:"workspace"`
	GraderInvocation    []string          `json:"grader_invocation"`
	GraderInvocationEnv map[string]string `json:"grader_invocation_env"`
}

func RegisterSetup(server *mcp.Server, cfg Config) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "setup",
		Description: "Get the problem description, available build configurations, workspace path, and the exact argv used to invoke the target during grading (grader_invocation).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input SetupInput) (*mcp.CallToolResult, SetupOutput, error) {
		idBytes, err := os.ReadFile(filepath.Join(cfg.ProblemDir, "id"))
		if err != nil {
			return nil, SetupOutput{}, fmt.Errorf("failed to read problem id: %w", err)
		}
		problemID := strings.TrimSpace(string(idBytes))

		promptBytes, err := os.ReadFile(filepath.Join(cfg.ProblemDir, "prompt"))
		if err != nil {
			return nil, SetupOutput{}, fmt.Errorf("failed to read prompt: %w", err)
		}

		configs := discoverConfigs(cfg.BinariesDir)

		return nil, SetupOutput{
			ID:                  problemID,
			Configs:             configs,
			Prompt:              string(promptBytes),
			Workspace:           cfg.WorkspaceDir,
			GraderInvocation:    GraderInvocation(cfg),
			GraderInvocationEnv: GraderInvocationEnv(cfg),
		}, nil
	})
}

func discoverConfigs(binariesDir string) []string {
	vulnDir := filepath.Join(binariesDir, "vuln")
	entries, err := os.ReadDir(vulnDir)
	if err != nil {
		return nil
	}
	var configs []string
	for _, e := range entries {
		if e.IsDir() {
			configs = append(configs, e.Name())
		}
	}
	return configs
}
