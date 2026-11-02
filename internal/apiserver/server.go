package apiserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/ignore"
	"github.com/joeyvictorino/tasia/internal/rules"
)

type APIServer struct {
	ScanPath   string
	Recursive  bool
	Port       int
	CORSOrigin string
}

type APIResponse struct {
	Status string      `json:"status"`
	Data   interface{} `json:"data,omitempty"`
	Error  string      `json:"error,omitempty"`
}

type ScanResult struct {
	Path         string          `json:"path"`
	FindingCount int             `json:"finding_count"`
	BySeverity   map[string]int  `json:"by_severity"`
	Findings     []rules.Finding `json:"findings"`
}

type StatsResult struct {
	Path         string         `json:"path"`
	FindingCount int            `json:"finding_count"`
	BySeverity   map[string]int `json:"by_severity"`
	RulesFired   int            `json:"rules_fired"`
	FilesScanned int            `json:"files_scanned"`
}

func NewServer(path string, port int, recursive bool) *APIServer {
	return &APIServer{
		ScanPath:   path,
		Recursive:  recursive,
		Port:       port,
		CORSOrigin: "*",
	}
}

func (s *APIServer) Start() error {
	return http.ListenAndServe(fmt.Sprintf(":%d", s.Port), s.Handler())
}

func (s *APIServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", s.cors(s.handleHealth))
	mux.HandleFunc("/api/v1/scan", s.cors(s.handleScan))
	mux.HandleFunc("/api/v1/findings", s.cors(s.handleFindings))
	mux.HandleFunc("/api/v1/rules", s.cors(s.handleRules))
	mux.HandleFunc("/api/v1/stats", s.cors(s.handleStats))
	return mux
}

func (s *APIServer) cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", s.CORSOrigin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, APIResponse{Status: "error", Error: "method not allowed"})
			return
		}
		next(w, r)
	}
}

func (s *APIServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, APIResponse{Status: "ok", Data: map[string]string{"service": "tasia"}})
}

func (s *APIServer) handleScan(w http.ResponseWriter, _ *http.Request) {
	findings, collected, err := s.runScan()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Error: err.Error()})
		return
	}
	sev := countBySeverity(findings)
	result := ScanResult{
		Path:         s.ScanPath,
		FindingCount: len(findings),
		BySeverity:   sev,
		Findings:     findings,
	}
	_ = collected
	writeJSON(w, http.StatusOK, APIResponse{Status: "ok", Data: result})
}

func (s *APIServer) handleFindings(w http.ResponseWriter, r *http.Request) {
	findings, _, err := s.runScan()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Error: err.Error()})
		return
	}

	if sev := r.URL.Query().Get("severity"); sev != "" {
		var filtered []rules.Finding
		for _, f := range findings {
			if strings.EqualFold(string(f.Severity), sev) {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}
	if ruleID := r.URL.Query().Get("rule"); ruleID != "" {
		var filtered []rules.Finding
		for _, f := range findings {
			if f.ID == ruleID {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	writeJSON(w, http.StatusOK, APIResponse{Status: "ok", Data: findings})
}

func (s *APIServer) handleRules(w http.ResponseWriter, _ *http.Request) {
	catalog := rules.Catalog()
	writeJSON(w, http.StatusOK, APIResponse{Status: "ok", Data: catalog})
}

func (s *APIServer) handleStats(w http.ResponseWriter, _ *http.Request) {
	findings, collected, err := s.runScan()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Error: err.Error()})
		return
	}

	fired := map[string]bool{}
	for _, f := range findings {
		fired[f.ID] = true
	}

	filesScanned := 0
	if collected != nil {
		filesScanned = collected.FilesScanned()
	}

	result := StatsResult{
		Path:         s.ScanPath,
		FindingCount: len(findings),
		BySeverity:   countBySeverity(findings),
		RulesFired:   len(fired),
		FilesScanned: filesScanned,
	}
	writeJSON(w, http.StatusOK, APIResponse{Status: "ok", Data: result})
}

func (s *APIServer) runScan() ([]rules.Finding, *collect.Collected, error) {
	absPath, err := filepath.Abs(s.ScanPath)
	if err != nil {
		return nil, nil, err
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return nil, nil, err
	}

	findings := rules.Evaluate(collected)
	if pol, err := ignore.Load(absPath); err == nil {
		pol.AddInline(ignore.ScanInline(absPath))
		findings = filterFindings(findings, pol)
	}
	return findings, collected, nil
}

func filterFindings(findings []rules.Finding, pol *ignore.Policy) []rules.Finding {
	var kept []rules.Finding
	for _, f := range findings {
		if !pol.SuppressesAt(f.ID, f.File, f.Line) {
			kept = append(kept, f)
		}
	}
	return kept
}

func countBySeverity(findings []rules.Finding) map[string]int {
	m := map[string]int{}
	for _, f := range findings {
		m[string(f.Severity)]++
	}
	return m
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
