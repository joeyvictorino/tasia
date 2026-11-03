package attacksurf

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type DimensionScore struct {
	Name  string  `json:"name"`
	Score float64 `json:"score"`
	Max   float64 `json:"max"`
	Notes []string `json:"notes,omitempty"`
}

type ServiceScore struct {
	Name       string           `json:"name"`
	File       string           `json:"file"`
	Total      float64          `json:"total"`
	Grade      string           `json:"grade"`
	Dimensions []DimensionScore `json:"dimensions"`
}

type Summary struct {
	TotalServices int     `json:"total_services"`
	OverallScore  float64 `json:"overall_score"`
	OverallGrade  string  `json:"overall_grade"`
	Critical      int     `json:"critical_services"`
	High          int     `json:"high_services"`
	Medium        int     `json:"medium_services"`
	Low           int     `json:"low_services"`
}

type Report struct {
	Services []ServiceScore `json:"services"`
	Summary  Summary        `json:"summary"`
}

func Analyze(collected *collect.Collected) Report {
	var services []ServiceScore

	for _, cf := range collected.ComposeFiles {
		for i := range cf.Services {
			ss := scoreService(&cf.Services[i], cf.Path)
			services = append(services, ss)
		}
	}

	sort.Slice(services, func(i, j int) bool {
		return services[i].Total > services[j].Total
	})

	summary := Summary{TotalServices: len(services)}
	var totalScore float64
	for _, s := range services {
		totalScore += s.Total
		switch {
		case s.Total >= 75:
			summary.Critical++
		case s.Total >= 50:
			summary.High++
		case s.Total >= 25:
			summary.Medium++
		default:
			summary.Low++
		}
	}
	if len(services) > 0 {
		summary.OverallScore = math.Round(totalScore/float64(len(services))*10) / 10
	}
	summary.OverallGrade = gradeFromScore(summary.OverallScore)

	return Report{Services: services, Summary: summary}
}

func scoreService(svc *compose.Service, file string) ServiceScore {
	dims := []DimensionScore{
		scoreNetwork(svc),
		scorePrivilege(svc),
		scoreDataAccess(svc),
		scoreIsolation(svc),
		scoreConfiguration(svc),
	}

	var total float64
	for _, d := range dims {
		total += d.Score
	}
	total = math.Min(total, 100)

	return ServiceScore{
		Name:       svc.Name,
		File:       file,
		Total:      math.Round(total*10) / 10,
		Grade:      gradeFromScore(total),
		Dimensions: dims,
	}
}

func scoreNetwork(svc *compose.Service) DimensionScore {
	d := DimensionScore{Name: "network_exposure", Max: 25}

	if svc.NetworkMode == "host" {
		d.Score += 20
		d.Notes = append(d.Notes, "network_mode: host exposes all host ports")
	}

	for _, p := range svc.Ports {
		if p.HostIP == "" || p.HostIP == "0.0.0.0" {
			d.Score += 3
			d.Notes = append(d.Notes, fmt.Sprintf("port %d bound to all interfaces", p.HostPort))
		} else {
			d.Score += 1
		}
	}

	if len(svc.DNS) > 0 {
		d.Score += 2
		d.Notes = append(d.Notes, "custom DNS configured")
	}

	d.Score = math.Min(d.Score, d.Max)
	return d
}

func scorePrivilege(svc *compose.Service) DimensionScore {
	d := DimensionScore{Name: "privilege_level", Max: 25}

	if svc.Privileged {
		d.Score += 25
		d.Notes = append(d.Notes, "privileged: true grants all capabilities")
		return d
	}

	dangerousCaps := map[string]float64{
		"SYS_ADMIN": 15, "SYS_PTRACE": 10, "NET_ADMIN": 8,
		"NET_RAW": 6, "DAC_OVERRIDE": 8, "SYS_RAWIO": 10,
		"SYS_MODULE": 12, "SETUID": 6, "SETGID": 6,
	}
	for _, cap := range svc.CapAdd {
		if score, ok := dangerousCaps[strings.ToUpper(cap)]; ok {
			d.Score += score
			d.Notes = append(d.Notes, fmt.Sprintf("cap_add: %s", cap))
		} else {
			d.Score += 2
		}
	}

	hasDropAll := false
	for _, cap := range svc.CapDrop {
		if strings.ToUpper(cap) == "ALL" {
			hasDropAll = true
		}
	}
	if !hasDropAll && len(svc.CapAdd) > 0 {
		d.Score += 5
		d.Notes = append(d.Notes, "capabilities added without cap_drop: [ALL]")
	}

	d.Score = math.Min(d.Score, d.Max)
	return d
}

func scoreDataAccess(svc *compose.Service) DimensionScore {
	d := DimensionScore{Name: "data_access", Max: 25}

	sensitivePatterns := []string{"/var/run/docker.sock", "/etc", "/root", "/home", "/proc", "/sys"}
	for _, v := range svc.Volumes {
		parts := strings.SplitN(v, ":", 2)
		src := parts[0]
		isRO := strings.Contains(v, ":ro")

		isSensitive := false
		for _, pat := range sensitivePatterns {
			if strings.HasPrefix(src, pat) || src == pat {
				isSensitive = true
				break
			}
		}

		if strings.Contains(src, "docker.sock") {
			d.Score += 15
			d.Notes = append(d.Notes, "Docker socket mounted — container escape vector")
		} else if src == "/" {
			d.Score += 12
			d.Notes = append(d.Notes, "root filesystem mounted")
		} else if isSensitive {
			if isRO {
				d.Score += 3
			} else {
				d.Score += 8
				d.Notes = append(d.Notes, fmt.Sprintf("sensitive path %s mounted writable", src))
			}
		} else {
			if isRO {
				d.Score += 0.5
			} else {
				d.Score += 1.5
			}
		}
	}

	for _, env := range svc.Environment {
		lower := strings.ToLower(env)
		if strings.Contains(lower, "password") || strings.Contains(lower, "secret") ||
			strings.Contains(lower, "api_key") || strings.Contains(lower, "token") {
			d.Score += 3
			d.Notes = append(d.Notes, "sensitive-looking environment variable")
			break
		}
	}

	d.Score = math.Min(d.Score, d.Max)
	return d
}

func scoreIsolation(svc *compose.Service) DimensionScore {
	d := DimensionScore{Name: "isolation", Max: 15}

	if svc.PidMode == "host" {
		d.Score += 5
		d.Notes = append(d.Notes, "PID namespace shared with host")
	}
	if svc.IpcMode == "host" {
		d.Score += 4
		d.Notes = append(d.Notes, "IPC namespace shared with host")
	}
	if svc.UsernsMode == "host" {
		d.Score += 4
		d.Notes = append(d.Notes, "user namespace shared with host")
	}

	if !svc.ReadOnly {
		d.Score += 2
		d.Notes = append(d.Notes, "root filesystem not read-only")
	}

	d.Score = math.Min(d.Score, d.Max)
	return d
}

func scoreConfiguration(svc *compose.Service) DimensionScore {
	d := DimensionScore{Name: "configuration", Max: 10}

	if svc.MemLimit == "" {
		d.Score += 3
		d.Notes = append(d.Notes, "no memory limit")
	}

	if svc.Healthcheck == nil {
		d.Score += 2
		d.Notes = append(d.Notes, "no healthcheck defined")
	}

	if svc.Restart == "" {
		d.Score += 1
		d.Notes = append(d.Notes, "no restart policy")
	}

	if len(svc.SecurityOpt) == 0 {
		d.Score += 2
		d.Notes = append(d.Notes, "no security options set")
	}

	if svc.OomKillDisable {
		d.Score += 2
		d.Notes = append(d.Notes, "OOM killer disabled")
	}

	d.Score = math.Min(d.Score, d.Max)
	return d
}

func gradeFromScore(score float64) string {
	switch {
	case score >= 75:
		return "F"
	case score >= 60:
		return "D"
	case score >= 45:
		return "C"
	case score >= 30:
		return "B"
	case score >= 15:
		return "B+"
	default:
		return "A"
	}
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Attack Surface Analysis (%d services, overall: %.1f/100 [%s])\n\n",
		r.Summary.TotalServices, r.Summary.OverallScore, r.Summary.OverallGrade)

	fmt.Fprintf(&b, "  Critical (>=75): %d   High (50-74): %d   Medium (25-49): %d   Low (<25): %d\n\n",
		r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Low)

	for _, s := range r.Services {
		fmt.Fprintf(&b, "  %s [%s] — %.1f/100 (%s)\n", s.Name, s.File, s.Total, s.Grade)
		for _, d := range s.Dimensions {
			bar := strings.Repeat("█", int(d.Score)) + strings.Repeat("░", int(d.Max-d.Score))
			fmt.Fprintf(&b, "    %-20s %5.1f/%5.1f  %s\n", d.Name, d.Score, d.Max, bar)
			for _, n := range d.Notes {
				fmt.Fprintf(&b, "      - %s\n", n)
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}
