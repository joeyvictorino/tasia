package nfsaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func makeCollected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func nfsService(name string, env []string, ports []compose.PortMapping, vols []string) compose.Service {
	return compose.Service{
		Name:        name,
		Image:       "erichough/nfs-server",
		Environment: env,
		Ports:       ports,
		Volumes:     vols,
	}
}

func TestNonNFSIgnored(t *testing.T) {
	svc := compose.Service{Name: "web", Image: "nginx:latest"}
	c := makeCollected(svc)
	r := Analyze(c)
	for _, sr := range r.Results {
		if len(sr.Findings) > 0 {
			t.Error("expected no findings for non-NFS service")
		}
	}
}

func TestNoAuthExport(t *testing.T) {
	svc := nfsService("nfs", []string{"NFS_EXPORT_OPTIONS=rw,sync,sec=sys"}, nil, nil)
	c := makeCollected(svc)
	r := Analyze(c)
	found := false
	for _, sr := range r.Results {
		for _, f := range sr.Findings {
			if f.Rule == "no_auth_export" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected no_auth_export finding for sec=sys")
	}
}

func TestNoExportConfig(t *testing.T) {
	svc := nfsService("nfs", nil, nil, nil)
	c := makeCollected(svc)
	r := Analyze(c)
	found := false
	for _, sr := range r.Results {
		for _, f := range sr.Findings {
			if f.Rule == "no_auth_export" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected no_auth_export finding for missing export config")
	}
}

func TestExportsVolumeOK(t *testing.T) {
	svc := nfsService("nfs", []string{"NFS_KERBEROS=true"}, nil, []string{"./exports:/etc/exports:ro"})
	c := makeCollected(svc)
	r := Analyze(c)
	for _, sr := range r.Results {
		for _, f := range sr.Findings {
			if f.Rule == "no_auth_export" {
				t.Error("should not flag no_auth_export when exports volume mounted")
			}
		}
	}
}

func TestWorldReadable(t *testing.T) {
	svc := nfsService("nfs", []string{"NFS_EXPORT_ALLOWED=*", "NFS_KERBEROS=true"}, nil, []string{"./exports:/etc/exports"})
	c := makeCollected(svc)
	r := Analyze(c)
	found := false
	for _, sr := range r.Results {
		for _, f := range sr.Findings {
			if f.Rule == "world_readable" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected world_readable finding")
	}
}

func TestNoRootSquash(t *testing.T) {
	svc := nfsService("nfs", []string{"NFS_EXPORT_OPTIONS=rw,no_root_squash,sec=krb5", "NFS_KERBEROS=true"}, nil, nil)
	c := makeCollected(svc)
	r := Analyze(c)
	found := false
	for _, sr := range r.Results {
		for _, f := range sr.Findings {
			if f.Rule == "no_root_squash" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected no_root_squash finding")
	}
}

func TestInsecurePort(t *testing.T) {
	svc := nfsService("nfs", []string{"NFS_EXPORT_OPTIONS=rw,insecure,sec=krb5", "NFS_KERBEROS=true"}, nil, nil)
	c := makeCollected(svc)
	r := Analyze(c)
	found := false
	for _, sr := range r.Results {
		for _, f := range sr.Findings {
			if f.Rule == "insecure_port" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected insecure_port finding")
	}
}

func TestMissingKerberos(t *testing.T) {
	svc := nfsService("nfs", nil, nil, []string{"./exports:/etc/exports"})
	c := makeCollected(svc)
	r := Analyze(c)
	found := false
	for _, sr := range r.Results {
		for _, f := range sr.Findings {
			if f.Rule == "missing_kerberos" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected missing_kerberos finding")
	}
}

func TestKerberosViaKeytab(t *testing.T) {
	svc := nfsService("nfs", nil, nil, []string{"./exports:/etc/exports", "./krb5.keytab:/etc/krb5.keytab"})
	c := makeCollected(svc)
	r := Analyze(c)
	for _, sr := range r.Results {
		for _, f := range sr.Findings {
			if f.Rule == "missing_kerberos" {
				t.Error("should not flag missing_kerberos when keytab volume exists")
			}
		}
	}
}

func TestExposedPort(t *testing.T) {
	ports := []compose.PortMapping{
		{HostPort: 2049, TargetPort: 2049, Raw: "0.0.0.0:2049:2049", HostIP: "0.0.0.0"},
	}
	svc := nfsService("nfs", []string{"NFS_KERBEROS=true"}, ports, []string{"./exports:/etc/exports"})
	c := makeCollected(svc)
	r := Analyze(c)
	found := false
	for _, sr := range r.Results {
		for _, f := range sr.Findings {
			if f.Rule == "exposed_port" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected exposed_port finding")
	}
}

func TestLocalhostNotExposed(t *testing.T) {
	ports := []compose.PortMapping{
		{HostPort: 2049, TargetPort: 2049, Raw: "127.0.0.1:2049:2049", HostIP: "127.0.0.1"},
	}
	svc := nfsService("nfs", []string{"NFS_KERBEROS=true"}, ports, []string{"./exports:/etc/exports"})
	c := makeCollected(svc)
	r := Analyze(c)
	for _, sr := range r.Results {
		for _, f := range sr.Findings {
			if f.Rule == "exposed_port" {
				t.Error("should not flag exposed_port for localhost binding")
			}
		}
	}
}

func TestSummaryCounts(t *testing.T) {
	svc := nfsService("nfs", []string{"NFS_EXPORT_ALLOWED=*", "NFS_EXPORT_OPTIONS=rw,no_root_squash,insecure,sec=sys"}, nil, nil)
	c := makeCollected(svc)
	r := Analyze(c)
	if r.Summary.AffectedServices != 1 {
		t.Errorf("expected 1 affected service, got %d", r.Summary.AffectedServices)
	}
	if r.Summary.TotalFindings < 3 {
		t.Errorf("expected at least 3 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatText(t *testing.T) {
	svc := nfsService("nfs", nil, nil, nil)
	c := makeCollected(svc)
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "NFS Share") {
		t.Error("expected NFS Share header")
	}
	if !strings.Contains(text, "nfs") {
		t.Error("expected service name in output")
	}
}

func TestFormatJSON(t *testing.T) {
	svc := nfsService("nfs", nil, nil, nil)
	c := makeCollected(svc)
	r := Analyze(c)
	j := FormatJSON(r)
	if !strings.Contains(j, "no_auth_export") {
		t.Error("expected rule in JSON output")
	}
}

func TestGaneshaNFS(t *testing.T) {
	svc := compose.Service{
		Name:  "ganesha",
		Image: "nfs-ganesha:latest",
	}
	c := makeCollected(svc)
	r := Analyze(c)
	found := false
	for _, sr := range r.Results {
		if len(sr.Findings) > 0 {
			found = true
		}
	}
	if !found {
		t.Error("expected findings for Ganesha NFS image")
	}
}
