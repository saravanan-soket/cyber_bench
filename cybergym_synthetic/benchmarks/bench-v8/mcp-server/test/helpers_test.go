//go:build functional || isolation

// Shared harness for MCP-over-docker test sessions.  Compiled into either
// `functional` or `isolation` builds — the two tags run disjoint test
// sets but share connection + JSON-RPC plumbing.
package test

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"testing"
	"time"
)

var testImage = flag.String("image", "", "Docker image to test against (required)")
var testServer = flag.String("server", "", "Path to local server binary to mount over /rlenv/mcp/server")

// Default `-parallel 4` since each test spawns its own docker container and
// the Go default (GOMAXPROCS) is usually too aggressive on shared dev boxes.
// User-supplied `-parallel N` still wins because m.Run() reparses CLI flags.
func TestMain(m *testing.M) {
	if err := flag.Set("test.parallel", "4"); err != nil {
		fmt.Fprintf(os.Stderr, "TestMain: failed to set default -parallel: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func requireImage(t *testing.T) string {
	t.Helper()
	if *testImage == "" {
		t.Skip("no -image flag provided")
	}
	return *testImage
}

// --- MCP session helpers ---

func jsonRPCRequest(id int, method string, params any) string {
	p, _ := json.Marshal(params)
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"%s","params":%s}`, id, method, string(p))
}

func jsonRPCNotification(method string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","method":"%s"}`, method)
}

type mcpSession struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Scanner
	nextID int
}

func newMCPSession(t *testing.T, image string) *mcpSession {
	t.Helper()

	args := []string{"run", "--rm", "-i"}
	if *testServer != "" {
		args = append(args, "-v", *testServer+":/rlenv/mcp/server:ro")
	}
	args = append(args, image)
	cmd := exec.Command("docker", args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start container: %v", err)
	}

	t.Cleanup(func() {
		stdin.Close()
		cmd.Wait()
	})

	scanner := bufio.NewScanner(stdoutPipe)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	s := &mcpSession{
		cmd:    cmd,
		stdin:  stdin,
		stdout: scanner,
		nextID: 1,
	}

	s.sendRaw(t, jsonRPCRequest(0, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "test", "version": "0.1"},
	}))
	s.sendRaw(t, jsonRPCNotification("notifications/initialized"))
	s.readResponse(t)

	return s
}

func (s *mcpSession) sendRaw(t *testing.T, msg string) {
	t.Helper()
	if _, err := fmt.Fprintln(s.stdin, msg); err != nil {
		t.Fatalf("failed to send: %v", err)
	}
}

func (s *mcpSession) callTool(t *testing.T, name string, args any) map[string]any {
	t.Helper()
	id := s.nextID
	s.nextID++

	s.sendRaw(t, jsonRPCRequest(id, "tools/call", map[string]any{
		"name":      name,
		"arguments": args,
	}))

	for {
		resp := s.readResponse(t)
		if respID, ok := resp["id"]; ok {
			if int(respID.(float64)) == id {
				if errObj, ok := resp["error"]; ok {
					t.Fatalf("tool %s returned error: %v", name, errObj)
				}
				return resp["result"].(map[string]any)
			}
		}
	}
}

func (s *mcpSession) readResponse(t *testing.T) map[string]any {
	t.Helper()
	done := make(chan struct{})
	var line string
	go func() {
		if s.stdout.Scan() {
			line = s.stdout.Text()
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(120 * time.Second):
		t.Fatal("timeout waiting for MCP response")
	}

	if line == "" {
		if err := s.stdout.Err(); err != nil {
			t.Fatalf("read error: %v", err)
		}
		t.Fatal("empty response from server")
	}

	var resp map[string]any
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		t.Fatalf("failed to parse response: %v\nraw: %s", err, line)
	}
	return resp
}

func extractStructured(result map[string]any) map[string]any {
	if sc, ok := result["structuredContent"]; ok {
		return sc.(map[string]any)
	}
	return nil
}

func getCaps(t *testing.T, sc map[string]any) map[string]interface{} {
	t.Helper()
	caps, _ := sc["capabilities"].(map[string]interface{})
	if caps == nil {
		t.Fatal("no capabilities in grade result")
	}
	return caps
}

func assertCap(t *testing.T, caps map[string]interface{}, name string, want bool) {
	t.Helper()
	got, _ := caps[name].(bool)
	if got != want {
		t.Errorf("capability %s: got %v, want %v (all caps: %v)", name, got, want, caps)
	}
}

func primitiveDetail(sc map[string]any, key string) string {
	details, ok := sc["details"].(map[string]any)
	if !ok {
		return ""
	}
	prim, ok := details["primitive"].(map[string]any)
	if !ok {
		return ""
	}
	v, ok := prim[key].(map[string]any)
	if !ok {
		return ""
	}
	s, _ := v["detail"].(string)
	return s
}

var pageMatchRe = regexp.MustCompile(`claimed_page=0x([0-9a-fA-F]+) expected_page=0x([0-9a-fA-F]+)`)

// parseClaimedExpected pulls (claimed_page, expected_page) out of an
// infoleak_* primitive detail line. Returns ok=false if the detail does
// not contain both pages — typically because the verifier wasn't reached
// (PoC crashed earlier or the primitive was wrong by more than a build
// drift).
func parseClaimedExpected(detail string) (claimed, expected uint64, ok bool) {
	m := pageMatchRe.FindStringSubmatch(detail)
	if m == nil {
		return 0, 0, false
	}
	c, err1 := strconv.ParseUint(m[1], 16, 64)
	e, err2 := strconv.ParseUint(m[2], 16, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return c, e, true
}
