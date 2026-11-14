package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const maxReadFileBytes = 128 * 1024 // 128 KB

// --- list_directory ---

type ListDirectoryInput struct {
	Path string `json:"path" jsonschema:"Absolute path to a directory"`
}

type FileEntry struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Size int64  `json:"size,omitempty"`
}

type ListDirectoryOutput struct {
	Entries []FileEntry `json:"entries"`
}

func RegisterListDirectory(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_directory",
		Description: "List directory contents with file names, types, and sizes.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ListDirectoryInput) (*mcp.CallToolResult, ListDirectoryOutput, error) {
		entries, err := os.ReadDir(input.Path)
		if err != nil {
			return nil, ListDirectoryOutput{}, fmt.Errorf("list_directory: %w", err)
		}

		var result []FileEntry
		for _, e := range entries {
			fe := FileEntry{Name: e.Name()}
			if e.IsDir() {
				fe.Type = "dir"
			} else {
				fe.Type = "file"
				if info, err := e.Info(); err == nil {
					fe.Size = info.Size()
				}
			}
			result = append(result, fe)
		}

		return nil, ListDirectoryOutput{Entries: result}, nil
	})
}

// --- read_file ---

type ReadFileInput struct {
	Path string `json:"path" jsonschema:"Absolute path to a file"`
}

type ReadFileOutput struct {
	Contents string `json:"contents"`
}

func RegisterReadFile(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "read_file",
		Description: "Read the contents of a file. Output is truncated to 128 KB; use exec with head/tail/sed for large files.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ReadFileInput) (*mcp.CallToolResult, ReadFileOutput, error) {
		data, err := os.ReadFile(input.Path)
		if err != nil {
			return nil, ReadFileOutput{}, fmt.Errorf("read_file: %w", err)
		}
		return nil, ReadFileOutput{Contents: truncateBytes(string(data), maxReadFileBytes)}, nil
	})
}

// --- write_file ---

type WriteFileInput struct {
	Path     string `json:"path" jsonschema:"Absolute path to write to"`
	Contents string `json:"contents" jsonschema:"File contents to write"`
}

type WriteFileOutput struct {
	Success bool   `json:"success"`
	Path    string `json:"path"`
}

func RegisterWriteFile(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "write_file",
		Description: "Write contents to a file. Creates parent directories if needed.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input WriteFileInput) (*mcp.CallToolResult, WriteFileOutput, error) {
		dir := filepath.Dir(input.Path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, WriteFileOutput{}, fmt.Errorf("write_file: mkdir: %w", err)
		}
		if err := os.WriteFile(input.Path, []byte(input.Contents), 0644); err != nil {
			return nil, WriteFileOutput{}, fmt.Errorf("write_file: %w", err)
		}
		return nil, WriteFileOutput{Success: true, Path: input.Path}, nil
	})
}
