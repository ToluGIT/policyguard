package junit

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"time"

	"github.com/ToluGIT/policyguard/pkg/types"
)

// Reporter implements the JUnit XML format reporter
type Reporter struct{}

// New creates a new JUnit reporter
func New() *Reporter {
	return &Reporter{}
}

// Generate creates a report from policy results
func (r *Reporter) Generate(ctx context.Context, result *types.PolicyResult, resources []types.Resource) (*types.Report, error) {
	report := &types.Report{
		ID:        fmt.Sprintf("report-%d", time.Now().Unix()),
		Timestamp: time.Now(),
		Resources: resources,
		Violations: result.Violations,
		Metadata:  result.Metadata,
	}

	// Calculate summary
	violationsBySeverity := make(map[string]int)
	for _, v := range result.Violations {
		violationsBySeverity[v.Severity]++
	}

	report.Summary = types.Summary{
		TotalResources:       len(resources),
		TotalViolations:      len(result.Violations),
		ViolationsBySeverity: violationsBySeverity,
		PassRate:             float64(len(resources)-len(result.Violations)) / float64(len(resources)) * 100,
	}

	return report, nil
}

// Write writes the report to the given writer in JUnit XML format
func (r *Reporter) Write(ctx context.Context, report *types.Report, writer io.Writer) error {
	testSuites := r.toJUnit(report)
	encoder := xml.NewEncoder(writer)
	encoder.Indent("", "  ")
	
	// Write XML header
	fmt.Fprintln(writer, `<?xml version="1.0" encoding="UTF-8"?>`)
	
	return encoder.Encode(testSuites)
}

// Format returns the format this reporter outputs
func (r *Reporter) Format() string {
	return "junit"
}

// JUnit XML structures
type testSuites struct {
	XMLName    xml.Name    `xml:"testsuites"`
	Name       string      `xml:"name,attr"`
	Tests      int         `xml:"tests,attr"`
	Failures   int         `xml:"failures,attr"`
	Errors     int         `xml:"errors,attr"`
	Time       float64     `xml:"time,attr"`
	TestSuites []testSuite `xml:"testsuite"`
}

type testSuite struct {
	Name      string     `xml:"name,attr"`
	Tests     int        `xml:"tests,attr"`
	Failures  int        `xml:"failures,attr"`
	Errors    int        `xml:"errors,attr"`
	Time      float64    `xml:"time,attr"`
	Timestamp string     `xml:"timestamp,attr"`
	TestCases []testCase `xml:"testcase"`
}

type testCase struct {
	Name      string   `xml:"name,attr"`
	ClassName string   `xml:"classname,attr"`
	Time      float64  `xml:"time,attr"`
	Failure   *failure `xml:"failure,omitempty"`
	Error     *failure `xml:"error,omitempty"`
}

type failure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

func (r *Reporter) toJUnit(report *types.Report) *testSuites {
	// Group violations by file
	fileViolations := make(map[string][]types.PolicyViolation)
	for _, violation := range report.Violations {
		file := violation.Location.File
		fileViolations[file] = append(fileViolations[file], violation)
	}

	// Create test suites
	var suites []testSuite
	totalFailures := 0
	totalErrors := 0

	for file, violations := range fileViolations {
		suite := testSuite{
			Name:      file,
			Tests:     len(violations),
			Timestamp: time.Now().Format(time.RFC3339),
			Time:      0.1, // Mock execution time
		}

		for _, violation := range violations {
			tc := testCase{
				Name:      fmt.Sprintf("%s_%s", violation.PolicyID, violation.ResourceID),
				ClassName: violation.PolicyID,
				Time:      0.01,
			}

			// Map severity to JUnit failure/error
			if violation.Severity == "critical" || violation.Severity == "high" {
				suite.Errors++
				totalErrors++
				tc.Error = &failure{
					Message: violation.Message,
					Type:    violation.PolicyID,
					Text:    fmt.Sprintf("%s\n\nDetails: %s\n\nRemediation: %s\n\nLocation: %s:%d:%d",
						violation.Message,
						violation.Details,
						violation.Remediation,
						violation.Location.File,
						violation.Location.Line,
						violation.Location.Column),
				}
			} else {
				suite.Failures++
				totalFailures++
				tc.Failure = &failure{
					Message: violation.Message,
					Type:    violation.PolicyID,
					Text:    fmt.Sprintf("%s\n\nDetails: %s\n\nRemediation: %s\n\nLocation: %s:%d:%d",
						violation.Message,
						violation.Details,
						violation.Remediation,
						violation.Location.File,
						violation.Location.Line,
						violation.Location.Column),
				}
			}

			suite.TestCases = append(suite.TestCases, tc)
		}

		suites = append(suites, suite)
	}

	// Add a success suite if no violations
	if len(report.Violations) == 0 {
		suites = append(suites, testSuite{
			Name:      "PolicyGuard Security Scan",
			Tests:     1,
			Timestamp: time.Now().Format(time.RFC3339),
			Time:      0.1,
			TestCases: []testCase{
				{
					Name:      "All security policies passed",
					ClassName: "PolicyGuard",
					Time:      0.01,
				},
			},
		})
	}

	return &testSuites{
		Name:     "PolicyGuard Security Scan Results",
		Tests:    len(report.Violations),
		Failures: totalFailures,
		Errors:   totalErrors,
		Time:     float64(len(report.Violations)) * 0.01,
		TestSuites: suites,
	}
}