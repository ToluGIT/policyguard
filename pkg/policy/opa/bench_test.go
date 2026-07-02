package opa

import (
	"context"
	"fmt"
	"testing"

	"github.com/ToluGIT/policyguard/pkg/types"
)

// genResources builds n synthetic aws_s3_bucket resources (each missing
// encryption/logging/public-access, so every policy that can fire does) to give
// the evaluator a realistic amount of work per resource.
func genResources(n int) []types.Resource {
	resources := make([]types.Resource, 0, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("bucket_%d", i)
		resources = append(resources, types.Resource{
			ID:       "aws_s3_bucket." + name,
			Type:     "aws_s3_bucket",
			Provider: "aws",
			Name:     name,
			Attributes: map[string]interface{}{
				"bucket": name,
				"acl":    "public-read-write",
			},
			Location: types.Location{File: "bench.tf", Line: i + 1, Column: 1},
		})
	}
	return resources
}

// benchEngine loads the full AWS policy set into an engine.
func benchEngine(b *testing.B) *Engine {
	b.Helper()
	e := New()
	if err := e.LoadPoliciesFromDirectory(context.Background(), "../../../policies"); err != nil {
		b.Fatalf("load policies: %v", err)
	}
	return e
}

// BenchmarkEvaluate measures end-to-end Evaluate throughput at a few corpus
// sizes. Run with:
//
//	go test ./pkg/policy/opa -bench BenchmarkEvaluate -benchmem -run '^$'
//
// Report resources/sec as: N (resources) / (ns/op / 1e9).
func BenchmarkEvaluate(b *testing.B) {
	for _, n := range []int{10, 100, 500} {
		b.Run(fmt.Sprintf("resources=%d", n), func(b *testing.B) {
			e := benchEngine(b)
			resources := genResources(n)
			ctx := context.Background()

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := e.Evaluate(ctx, resources); err != nil {
					b.Fatalf("evaluate: %v", err)
				}
			}
		})
	}
}
