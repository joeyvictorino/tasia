package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type DoctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type DoctorReport struct {
	Checks []DoctorCheck `json:"checks"`
	Ready  bool          `json:"ready"`
}

func checkBinary(name string) DoctorCheck {
	_, err := exec.LookPath(name)
	if err != nil {
		return DoctorCheck{Name: name, Status: "fail", Message: fmt.Sprintf("%s not found in PATH", name)}
	}
	return DoctorCheck{Name: name, Status: "pass", Message: fmt.Sprintf("%s is available", name)}
}

func checkFileExists(path, label, level string) DoctorCheck {
	if _, err := os.Stat(path); err == nil {
		return DoctorCheck{Name: label, Status: "pass", Message: fmt.Sprintf("%s found", path)}
	}
	return DoctorCheck{Name: label, Status: level, Message: fmt.Sprintf("%s not found", path)}
}

func checkGitRepo(path string) DoctorCheck {
	gitDir := filepath.Join(path, ".git")
	if info, err := os.Stat(gitDir); err == nil && info.IsDir() {
		return DoctorCheck{Name: "git-repo", Status: "pass", Message: "directory is a git repository"}
	}
	return DoctorCheck{Name: "git-repo", Status: "warn", Message: "directory is not a git repository (hooks won't work)"}
}

func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	path := fs.String("path", ".", "directory to check")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	var checks []DoctorCheck

	checks = append(checks, checkBinary("docker"))
	checks = append(checks, checkBinary("docker-compose"))
	checks = append(checks, checkGitRepo(absPath))

	hasConfig := false
	for _, name := range []string{".tasiarc.yaml", ".tasiarc.yml"} {
		cfgPath := filepath.Join(absPath, name)
		if _, err := os.Stat(cfgPath); err == nil {
			hasConfig = true
			checks = append(checks, DoctorCheck{Name: "config", Status: "pass", Message: fmt.Sprintf("found %s", name)})
			break
		}
	}
	if !hasConfig {
		checks = append(checks, DoctorCheck{Name: "config", Status: "warn", Message: "no .tasiarc.yaml found (using defaults)"})
	}

	ignorePath := filepath.Join(absPath, ".tasiaignore")
	checks = append(checks, checkFileExists(ignorePath, "tasiaignore", "warn"))

	rulesDir := filepath.Join(absPath, ".tasia")
	if _, err := os.Stat(rulesDir); err == nil {
		rulesFile := filepath.Join(rulesDir, "rules.yaml")
		checks = append(checks, checkFileExists(rulesFile, "custom-rules", "warn"))
	}

	ready := true
	for _, c := range checks {
		if c.Status == "fail" {
			ready = false
			break
		}
	}

	report := DoctorReport{Checks: checks, Ready: ready}

	switch *format {
	case "json":
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	default:
		fmt.Println("Environment Check:")
		fmt.Println()
		for _, c := range report.Checks {
			icon := "?"
			switch c.Status {
			case "pass":
				icon = "ok"
			case "warn":
				icon = "!!"
			case "fail":
				icon = "XX"
			}
			fmt.Printf("  [%s] %-18s %s\n", icon, c.Name, c.Message)
		}
		fmt.Println()
		if report.Ready {
			fmt.Println("Ready to scan.")
		} else {
			fmt.Println("Some required tools are missing.")
		}
	}

	return nil
}
