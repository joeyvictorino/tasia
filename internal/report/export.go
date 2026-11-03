package report

import (
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/rules"
)

// ExportCSV writes findings as CSV with columns: severity, rule_id, title, file, line, evidence.
func ExportCSV(findings []rules.Finding, w io.Writer) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	if err := cw.Write([]string{"severity", "rule_id", "title", "file", "line", "evidence"}); err != nil {
		return err
	}
	for _, f := range findings {
		if err := cw.Write([]string{
			string(f.Severity),
			f.ID,
			f.Title,
			f.File,
			fmt.Sprintf("%d", f.Line),
			f.Evidence,
		}); err != nil {
			return err
		}
	}
	return cw.Error()
}

// ExportMarkdown writes findings as a Markdown document grouped by severity.
func ExportMarkdown(findings []rules.Finding, w io.Writer) error {
	fmt.Fprintf(w, "# Tasia Security Findings\n\n")
	fmt.Fprintf(w, "Total: %d findings\n\n", len(findings))

	if len(findings) == 0 {
		fmt.Fprintf(w, "No findings.\n")
		return nil
	}

	grouped := map[rules.Severity][]rules.Finding{}
	for _, f := range findings {
		grouped[f.Severity] = append(grouped[f.Severity], f)
	}

	order := []rules.Severity{rules.SeverityCritical, rules.SeverityHigh, rules.SeverityMedium, rules.SeverityLow}
	for _, sev := range order {
		fs := grouped[sev]
		if len(fs) == 0 {
			continue
		}
		sort.Slice(fs, func(i, j int) bool { return fs[i].ID < fs[j].ID })
		fmt.Fprintf(w, "## %s (%d)\n\n", sev, len(fs))
		fmt.Fprintf(w, "| Rule | Title | File | Line | Evidence |\n")
		fmt.Fprintf(w, "|------|-------|------|------|----------|\n")
		for _, f := range fs {
			fmt.Fprintf(w, "| %s | %s | %s | %d | %s |\n",
				f.ID, escMD(f.Title), escMD(f.File), f.Line, escMD(f.Evidence))
		}
		fmt.Fprintf(w, "\n")
	}
	return nil
}

func escMD(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// JUnit XML types for ExportJUnit.
type junitTestSuites struct {
	XMLName xml.Name         `xml:"testsuites"`
	Suites  []junitTestSuite `xml:"testsuite"`
}

type junitTestSuite struct {
	Name     string          `xml:"name,attr"`
	Tests    int             `xml:"tests,attr"`
	Failures int             `xml:"failures,attr"`
	Cases    []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

// ExportJUnit writes findings as JUnit XML (each finding is a test failure).
func ExportJUnit(findings []rules.Finding, w io.Writer) error {
	var cases []junitTestCase
	for _, f := range findings {
		tc := junitTestCase{
			Name:      fmt.Sprintf("%s: %s", f.ID, f.Title),
			Classname: f.File,
			Failure: &junitFailure{
				Message: f.Title,
				Type:    string(f.Severity),
				Body:    fmt.Sprintf("File: %s\nLine: %d\nEvidence: %s\nWhy: %s\nFix: %s", f.File, f.Line, f.Evidence, f.Why, f.Fix),
			},
		}
		cases = append(cases, tc)
	}

	suites := junitTestSuites{
		Suites: []junitTestSuite{{
			Name:     "tasia",
			Tests:    len(findings),
			Failures: len(findings),
			Cases:    cases,
		}},
	}

	fmt.Fprintf(w, xml.Header)
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(suites); err != nil {
		return err
	}
	fmt.Fprintf(w, "\n")
	return nil
}
