package grader

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
)

// CompositeGrader runs all registered SubGraders in parallel and merges
// their capabilities into a single GradeResult.
type CompositeGrader struct {
	SubGraders []SubGrader
}

type subResult struct {
	name    string
	caps    map[string]bool
	details interface{}
	err     error
}

func (g *CompositeGrader) Grade(ctx context.Context, req GradeRequest) (*GradeResult, error) {
	results := make([]subResult, len(g.SubGraders))

	var wg sync.WaitGroup
	for i, sg := range g.SubGraders {
		wg.Add(1)
		go func(idx int, s SubGrader) {
			defer wg.Done()
			caps, details, err := s.Check(ctx, req)
			results[idx] = subResult{
				name:    s.Name(),
				caps:    caps,
				details: details,
				err:     err,
			}
		}(i, sg)
	}
	wg.Wait()

	merged := make(map[string]bool)
	var details GradeDetails

	for _, r := range results {
		if r.err != nil {
			log.Printf("grader: sub-grader %q failed: %v", r.name, r.err)
			continue
		}
		for k, v := range r.caps {
			if v {
				merged[k] = true
			}
		}
		if r.details != nil {
			switch r.name {
			case "coverage":
				if d, ok := r.details.(*CoverageResult); ok {
					details.Coverage = d
				}
			case "diff":
				if d, ok := r.details.(*DiffResult); ok {
					details.Diff = d
				}
			case "primitive":
				if d, ok := r.details.(*PrimitiveResult); ok {
					details.Primitive = d
				}
			}
		}
	}

	var trueCaps []string
	for k, v := range merged {
		if v {
			trueCaps = append(trueCaps, k)
		}
	}
	sort.Strings(trueCaps)

	reason := fmt.Sprintf("%d capabilities [%s]", len(trueCaps), strings.Join(trueCaps, ", "))
	if len(trueCaps) == 0 {
		reason = "no capabilities detected"
	}
	// Append a coverage hit ratio when the coverage grader ran. Visible at
	// the top level so partial-hit patterns are obvious without digging
	// into details — e.g. "1 capabilities [diff]; cov 0/3 patched lines".
	if details.Coverage != nil && details.Coverage.TotalPatched > 0 {
		reason += fmt.Sprintf("; cov %d/%d patched lines",
			details.Coverage.HitPatched, details.Coverage.TotalPatched)
	}

	return &GradeResult{
		Capabilities: merged,
		Reason:       reason,
		Details:      details,
	}, nil
}
