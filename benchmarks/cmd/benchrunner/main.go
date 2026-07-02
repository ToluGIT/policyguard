// Command benchrunner measures PolicyGuard's detection precision and recall
// against a labeled corpus.
//
// It parses each .tf fixture in benchmarks/corpus/, evaluates it through the
// real OPA engine, and compares the findings to the independent ground-truth
// labels in benchmarks/labels.json. The comparison is scoped to the
// core_policies set so the number reflects the unambiguous core-security
// policies rather than opinionated style/tagging checks.
//
//	TP = a labeled (file, resource, policy) that PolicyGuard reported
//	FP = a core-policy finding PolicyGuard reported that is NOT labeled
//	FN = a labeled finding PolicyGuard did NOT report
//
// Precision = TP / (TP + FP), Recall = TP / (TP + FN), F1 = harmonic mean.
//
// Usage:
//
//	go run ./benchmarks/cmd/benchrunner \
//	  [-corpus benchmarks/corpus] [-labels benchmarks/labels.json] \
//	  [-policies policies] [-min-precision 0.0] [-min-recall 0.0] [-json]
//
// Exit codes: 0 = ran and met thresholds, 1 = below a threshold, 2 = error.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/ToluGIT/policyguard/pkg/parser/terraform"
	"github.com/ToluGIT/policyguard/pkg/policy/opa"
)

// labelsFile is the on-disk schema of benchmarks/labels.json.
type labelsFile struct {
	Description  string               `json:"description"`
	CorePolicies []string             `json:"core_policies"`
	Files        map[string]fileLabel `json:"files"`
}

type fileLabel struct {
	Expected []expectedViolation `json:"expected"`
	Note     string              `json:"note,omitempty"`
}

type expectedViolation struct {
	ResourceID string `json:"resource_id"`
	PolicyID   string `json:"policy_id"`
}

// key uniquely identifies a finding within a single fixture file.
type key struct {
	resourceID string
	policyID   string
}

func (k key) String() string { return k.resourceID + " / " + k.policyID }

// fileResult holds the per-file comparison outcome.
type fileResult struct {
	file string
	tp   []key
	fp   []key
	fn   []key
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "benchrunner: %v\n", err)
		os.Exit(2)
	}
}

func run() error {
	var (
		corpusDir    = flag.String("corpus", "benchmarks/corpus", "directory of .tf fixtures")
		labelsPath   = flag.String("labels", "benchmarks/labels.json", "ground-truth labels file")
		policiesDir  = flag.String("policies", "policies", "policy directory to load")
		minPrecision = flag.Float64("min-precision", 0.0, "fail (exit 1) if precision is below this")
		minRecall    = flag.Float64("min-recall", 0.0, "fail (exit 1) if recall is below this")
		asJSON       = flag.Bool("json", false, "emit machine-readable JSON instead of a table")
	)
	flag.Parse()

	labels, err := loadLabels(*labelsPath)
	if err != nil {
		return err
	}
	core := map[string]bool{}
	for _, p := range labels.CorePolicies {
		core[p] = true
	}

	ctx := context.Background()

	// Compare each labeled fixture independently. Parsing per-file keeps each
	// finding attributable to its source fixture and avoids cross-file resource
	// ID collisions.
	files := make([]string, 0, len(labels.Files))
	for f := range labels.Files {
		files = append(files, f)
	}
	sort.Strings(files)

	var results []fileResult
	var totalTP, totalFP, totalFN int

	for _, fname := range files {
		fpath := filepath.Join(*corpusDir, fname)
		if _, statErr := os.Stat(fpath); statErr != nil {
			return fmt.Errorf("labeled fixture %q not found: %w", fname, statErr)
		}

		// A fresh engine per file: load policies, evaluate, collect findings.
		// (LoadPoliciesFromDirectory recompiles the full set; cheap for a small
		// corpus and keeps each run independent.)
		found, evalErr := scanFile(ctx, fpath, *policiesDir)
		if evalErr != nil {
			return fmt.Errorf("scanning %s: %w", fname, evalErr)
		}

		// Restrict the reported findings to the core-policy set; anything else is
		// out of scope and neither rewarded nor penalized.
		foundCore := map[key]bool{}
		for k := range found {
			if core[k.policyID] {
				foundCore[k] = true
			}
		}

		expected := map[key]bool{}
		for _, e := range labels.Files[fname].Expected {
			expected[key{e.ResourceID, e.PolicyID}] = true
		}

		res := fileResult{file: fname}
		for k := range expected {
			if foundCore[k] {
				res.tp = append(res.tp, k)
			} else {
				res.fn = append(res.fn, k)
			}
		}
		for k := range foundCore {
			if !expected[k] {
				res.fp = append(res.fp, k)
			}
		}
		sortKeys(res.tp)
		sortKeys(res.fp)
		sortKeys(res.fn)

		totalTP += len(res.tp)
		totalFP += len(res.fp)
		totalFN += len(res.fn)
		results = append(results, res)
	}

	precision := ratio(totalTP, totalTP+totalFP)
	recall := ratio(totalTP, totalTP+totalFN)
	f1 := 0.0
	if precision+recall > 0 {
		f1 = 2 * precision * recall / (precision + recall)
	}

	if *asJSON {
		emitJSON(results, len(files), len(core), totalTP, totalFP, totalFN, precision, recall, f1)
	} else {
		emitTable(results, len(files), len(core), totalTP, totalFP, totalFN, precision, recall, f1)
	}

	// CI gate: fail if below a stated threshold.
	if precision < *minPrecision {
		fmt.Fprintf(os.Stderr, "\nFAIL: precision %.4f < min %.4f\n", precision, *minPrecision)
		os.Exit(1)
	}
	if recall < *minRecall {
		fmt.Fprintf(os.Stderr, "\nFAIL: recall %.4f < min %.4f\n", recall, *minRecall)
		os.Exit(1)
	}
	return nil
}

// scanFile parses a single fixture and evaluates it, returning the set of
// (resource_id, policy_id) findings.
func scanFile(ctx context.Context, fpath, policiesDir string) (map[key]bool, error) {
	parser := terraform.New()
	engine := opa.New()
	if err := engine.LoadPoliciesFromDirectory(ctx, policiesDir); err != nil {
		return nil, fmt.Errorf("loading policies: %w", err)
	}

	resources, err := parser.Parse(ctx, fpath)
	if err != nil {
		return nil, fmt.Errorf("parsing: %w", err)
	}

	result, err := engine.Evaluate(ctx, resources)
	if err != nil {
		return nil, fmt.Errorf("evaluating: %w", err)
	}

	found := map[key]bool{}
	for _, v := range result.Violations {
		found[key{v.ResourceID, v.PolicyID}] = true
	}
	return found, nil
}

func loadLabels(path string) (*labelsFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading labels: %w", err)
	}
	var lf labelsFile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("parsing labels JSON: %w", err)
	}
	if len(lf.CorePolicies) == 0 {
		return nil, fmt.Errorf("labels file has no core_policies")
	}
	if len(lf.Files) == 0 {
		return nil, fmt.Errorf("labels file has no files")
	}
	return &lf, nil
}

func ratio(num, den int) float64 {
	if den == 0 {
		return 1.0 // no opportunities to be wrong in this dimension
	}
	return float64(num) / float64(den)
}

func sortKeys(ks []key) {
	sort.Slice(ks, func(i, j int) bool {
		if ks[i].resourceID != ks[j].resourceID {
			return ks[i].resourceID < ks[j].resourceID
		}
		return ks[i].policyID < ks[j].policyID
	})
}

func emitTable(results []fileResult, nFiles, nCore, tp, fp, fn int, precision, recall, f1 float64) {
	fmt.Println("PolicyGuard detection benchmark")
	fmt.Printf("corpus: %d fixtures | scope: %d core policies\n", nFiles, nCore)
	fmt.Println("------------------------------------------------------------")
	for _, r := range results {
		fmt.Printf("%-32s TP=%d FP=%d FN=%d\n", r.file, len(r.tp), len(r.fp), len(r.fn))
		for _, k := range r.fp {
			fmt.Printf("    FP  %s\n", k)
		}
		for _, k := range r.fn {
			fmt.Printf("    FN  %s\n", k)
		}
	}
	fmt.Println("------------------------------------------------------------")
	fmt.Printf("TP=%d  FP=%d  FN=%d\n", tp, fp, fn)
	fmt.Printf("Precision=%.4f  Recall=%.4f  F1=%.4f\n", precision, recall, f1)
}

func emitJSON(results []fileResult, nFiles, nCore, tp, fp, fn int, precision, recall, f1 float64) {
	type fileOut struct {
		File string   `json:"file"`
		TP   int      `json:"tp"`
		FP   []string `json:"fp"`
		FN   []string `json:"fn"`
	}
	out := struct {
		Fixtures     int       `json:"fixtures"`
		CorePolicies int       `json:"core_policies"`
		TP           int       `json:"tp"`
		FP           int       `json:"fp"`
		FN           int       `json:"fn"`
		Precision    float64   `json:"precision"`
		Recall       float64   `json:"recall"`
		F1           float64   `json:"f1"`
		Files        []fileOut `json:"files"`
	}{
		Fixtures: nFiles, CorePolicies: nCore,
		TP: tp, FP: fp, FN: fn,
		Precision: precision, Recall: recall, F1: f1,
	}
	for _, r := range results {
		fo := fileOut{File: r.file, TP: len(r.tp)}
		for _, k := range r.fp {
			fo.FP = append(fo.FP, k.String())
		}
		for _, k := range r.fn {
			fo.FN = append(fo.FN, k.String())
		}
		out.Files = append(out.Files, fo)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}
