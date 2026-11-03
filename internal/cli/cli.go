// Package cli implements tasia's command-line interface: review, ci,
// install/uninstall, explain, rules, schema and version commands. It
// wires together collect, rules, ignore, config and report into the
// scan-evaluate-decide-output pipeline.
package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/config"
	"github.com/joeyvictorino/tasia/internal/ignore"
	"github.com/joeyvictorino/tasia/internal/llm"
	"github.com/joeyvictorino/tasia/internal/report"
	"github.com/joeyvictorino/tasia/internal/rules"
)

// Build metadata, overridden at release time via -ldflags.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// versionString prefers the ldflags value, then the module version embedded by
// `go install` (so `go install ...@latest` shows the real tag, not "dev").
func versionString() string {
	if Version != "" && Version != "dev" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return Version
}

// Run parses args and dispatches commands. Thin layer.
func Run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}

	cmd := args[0]
	switch cmd {
	case "review":
		return runReview(args[1:])
	case "diff":
		return runDiff(args[1:])
	case "check":
		return runCheck(args[1:])
	case "ci":
		return runCI(args[1:])
	case "fix":
		return runFix(args[1:])
	case "install":
		return runInstall(args[1:])
	case "uninstall":
		return runUninstall(args[1:])
	case "explain":
		return runExplain(args[1:])
	case "rules":
		return runRules(args[1:])
	case "schema":
		return runSchema(args[1:])
	case "init":
		return runInit(args[1:])
	case "watch":
		return runWatch(args[1:])
	case "profile":
		return runProfile(args[1:])
	case "report":
		return runReport(args[1:])
	case "compare":
		return runCompare(args[1:])
	case "export":
		return runExport(args[1:])
	case "validate":
		return runValidate(args[1:])
	case "fmt":
		return runFmt(args[1:])
	case "migrate":
		return runMigrate(args[1:])
	case "baseline":
		return runBaseline(args[1:])
	case "severity":
		return runSeverity(args[1:])
	case "inventory":
		return runInventory(args[1:])
	case "graph":
		return runGraph(args[1:])
	case "lint":
		return runLint(args[1:])
	case "doctor":
		return runDoctor(args[1:])
	case "scan":
		return runScanCmd(args[1:])
	case "ignore":
		return runIgnoreCmd(args[1:])
	case "suggest":
		return runSuggest(args[1:])
	case "history":
		return runHistory(args[1:])
	case "metrics":
		return runMetrics(args[1:])
	case "tags":
		return runTags(args[1:])
	case "summary":
		return runSummaryCmd(args[1:])
	case "trends":
		return runTrendsCmd(args[1:])
	case "bench":
		return runBench(args[1:])
	case "deps":
		return runDeps(args[1:])
	case "matrix":
		return runMatrix(args[1:])
	case "compliance":
		return runCompliance(args[1:])
	case "coverage":
		return runCoverage(args[1:])
	case "policy":
		return runPolicy(args[1:])
	case "audit-trail":
		return runAuditTrail(args[1:])
	case "network":
		return runNetwork(args[1:])
	case "secrets-scan":
		return runSecretsScan(args[1:])
	case "changelog":
		return runChangelog(args[1:])
	case "status":
		return runStatus(args[1:])
	case "config-test":
		return runConfigTest(args[1:])
	case "env-audit":
		return runEnvAudit(args[1:])
	case "hotspots":
		return runHotspots(args[1:])
	case "prioritize":
		return runPrioritize(args[1:])
	case "sbom":
		return runSBOM(args[1:])
	case "risk-matrix":
		return runRiskMatrix(args[1:])
	case "benchmark-rules":
		return runBenchmarkRules(args[1:])
	case "snapshot":
		return runSnapshot(args[1:])
	case "drift":
		return runDrift(args[1:])
	case "api":
		return runAPI(args[1:])
	case "config-check":
		return runConfigCheck(args[1:])
	case "merge-check":
		return runMergeCheck(args[1:])
	case "port-map":
		return runPortMap(args[1:])
	case "capabilities":
		return runCapabilities(args[1:])
	case "entropy":
		return runEntropy(args[1:])
	case "isolation":
		return runIsolation(args[1:])
	case "volumes":
		return runVolumes(args[1:])
	case "healthcheck":
		return runHealthcheck(args[1:])
	case "logging":
		return runLogging(args[1:])
	case "resource-limits":
		return runResourceLimits(args[1:])
	case "tmpfs":
		return runTmpfs(args[1:])
	case "dns":
		return runDns(args[1:])
	case "labels":
		return runLabels(args[1:])
	case "cgroups":
		return runCgroups(args[1:])
	case "signals":
		return runSignals(args[1:])
	case "user-ns":
		return runUserns(args[1:])
	case "seccomp":
		return runSeccomp(args[1:])
	case "pid-ns":
		return runPidns(args[1:])
	case "ipc":
		return runIpcNS(args[1:])
	case "sysctls":
		return runSysctls(args[1:])
	case "devices":
		return runDevices(args[1:])
	case "ulimits":
		return runUlimits(args[1:])
	case "runtime":
		return runRuntimeAudit(args[1:])
	case "depends":
		return runDepends(args[1:])
	case "entrypoint":
		return runEntrypoint(args[1:])
	case "env-isolation":
		return runEnvIsolation(args[1:])
	case "build-args":
		return runBuildArgs(args[1:])
	case "net-audit":
		return runNetAudit(args[1:])
	case "init-process":
		return runInitProcess(args[1:])
	case "oom":
		return runOom(args[1:])
	case "restart-policy":
		return runRestartPolicy(args[1:])
	case "stop-grace":
		return runStopGrace(args[1:])
	case "shm-size":
		return runShmSize(args[1:])
	case "workdir":
		return runWorkdir(args[1:])
	case "copy-add":
		return runCopyAdd(args[1:])
	case "privileged":
		return runPrivileged(args[1:])
	case "workload":
		return runWorkload(args[1:])
	case "image-trust":
		return runImageTrust(args[1:])
	case "attack-surface":
		return runAttacksurf(args[1:])
	case "layer-trust":
		return runLayerTrust(args[1:])
	case "compose-lint":
		return runComposeLint(args[1:])
	case "registry":
		return runRegistry(args[1:])
	case "sidecar":
		return runSidecar(args[1:])
	case "service-map":
		return runServiceMap(args[1:])
	case "image-age":
		return runImageAge(args[1:])
	case "layer-audit":
		return runLayerAudit(args[1:])
	case "multi-stage":
		return runMultistage(args[1:])
	case "build-cache":
		return runBuildCache(args[1:])
	case "readonly-fs":
		return runReadonlyFS(args[1:])
	case "env-leak":
		return runEnvLeak(args[1:])
	case "egress":
		return runEgress(args[1:])
	case "credential-scan":
		return runCredentialScan(args[1:])
	case "compose-override":
		return runComposeOverride(args[1:])
	case "egress-map":
		return runEgressMap(args[1:])
	case "service-mesh":
		return runServiceMesh(args[1:])
	case "service-dep":
		return runServiceDep(args[1:])
	case "health-probe":
		return runHealthProbe(args[1:])
	case "apparmor":
		return runAppArmor(args[1:])
	case "selinux":
		return runSELinux(args[1:])
	case "proc-ns":
		return runProcNS(args[1:])
	case "readonly-root":
		return runReadOnlyRoot(args[1:])
	case "compose-validate":
		return runComposeValidate(args[1:])
	case "port-conflict":
		return runPortConflict(args[1:])
	case "volume-audit":
		return runVolumeAudit(args[1:])
	case "env-scan":
		return runEnvScan(args[1:])
	case "uts-ns":
		return runUtsNS(args[1:])
	case "cgroupv2":
		return runCgroupV2(args[1:])
	case "ipc-ns":
		return runIpcNS(args[1:])
	case "net-ns":
		return runNetNS(args[1:])
	case "cgroup-ns":
		return runCgroupNS(args[1:])
	case "mnt-ns":
		return runMntNS(args[1:])
	case "log-driver":
		return runLogDriver(args[1:])
	case "cpu-pin":
		return runCpuPin(args[1:])
	case "cpu-shares":
		return runCpuShares(args[1:])
	case "dep-chain":
		return runDepChain(args[1:])
	case "image-pin":
		return runImagePin(args[1:])
	case "graceful":
		return runGraceful(args[1:])
	case "cpuset":
		return runCpuset(args[1:])
	case "tty":
		return runTty(args[1:])
	case "memswap":
		return runMemswap(args[1:])
	case "blkio":
		return runBlkio(args[1:])
	case "bind-prop":
		return runBindProp(args[1:])
	case "net-analyze":
		return runNetAnalyze(args[1:])
	case "rate-limit":
		return runRateLimit(args[1:])
	case "deploy-policy":
		return runDeploypol(args[1:])
	case "noexec":
		return runNoexec(args[1:])
	case "socket-audit":
		return runSocketAudit(args[1:])
	case "pidsec":
		return runPidsec(args[1:])
	case "confinement":
		return runConfinement(args[1:])
	case "tmpdir":
		return runTmpdir(args[1:])
	case "credleak":
		return runCredleak(args[1:])
	case "logsecrets":
		return runLogsecrets(args[1:])
	case "socketperm":
		return runSocketperm(args[1:])
	case "pullpolicy":
		return runPullpolicy(args[1:])
	case "hostpath":
		return runHostpath(args[1:])
	case "netfilter":
		return runNetfilter(args[1:])
	case "logdriver":
		return runLogdriver(args[1:])
	case "copyadd":
		return runCopyadd(args[1:])
	case "buildcache":
		return runBuildcache(args[1:])
	case "layeraudit":
		return runLayeraudit(args[1:])
	case "envfile":
		return runEnvfile(args[1:])
	case "healthz":
		return runHealthz(args[1:])
	case "gpu-passthrough":
		return runGpupass(args[1:])
	case "compose-network":
		return runComposenet(args[1:])
	case "registryauth":
		return runRegistryauth(args[1:])
	case "dnsrebind":
		return runDnsrebind(args[1:])
	case "fileperm":
		return runFileperm(args[1:])
	case "logrotate":
		return runLogrotate(args[1:])
	case "proberesist":
		return runProberesist(args[1:])
	case "cronaudit":
		return runCronaudit(args[1:])
	case "ipblock":
		return runIpblock(args[1:])
	case "certpin":
		return runCertpin(args[1:])
	case "userlookup":
		return runUserlookup(args[1:])
	case "capbound":
		return runCapbound(args[1:])
	case "ipcaudit":
		return runIpcaudit(args[1:])
	case "procmount":
		return runProcmount(args[1:])
	case "cgroupquota":
		return runCgroupquota(args[1:])
	case "tmpexec":
		return runTmpexec(args[1:])
	case "kernelparam":
		return runKernelparam(args[1:])
	case "gracefulshutdown":
		return runGracefulshutdown(args[1:])
	case "pidlimit":
		return runPidlimit(args[1:])
	case "swaplimit":
		return runSwaplimit(args[1:])
	case "fdlimit":
		return runFdlimit(args[1:])
	case "loopdev":
		return runLoopdev(args[1:])
	case "storagedriver":
		return runStoragedriver(args[1:])
	case "networkisolation":
		return runNetworkisolation(args[1:])
	case "apiexpose":
		return runApiexpose(args[1:])
	case "oauth2audit":
		return runOauth2audit(args[1:])
	case "apigateway":
		return runApigateway(args[1:])
	case "envinjection":
		return runEnvinjection(args[1:])
	case "ptraceprotect":
		return runPtraceprotect(args[1:])
	case "tmpwatch":
		return runTmpwatch(args[1:])
	case "envexpand":
		return runEnvexpand(args[1:])
	case "volperm":
		return runVolperm(args[1:])
	case "secretrotation":
		return runSecretrotation(args[1:])
	case "timezoneleak":
		return runTimezoneleak(args[1:])
	case "logforward":
		return runLogforward(args[1:])
	case "cronjob":
		return runCronjob(args[1:])
	case "filedescriptor":
		return runFiledescriptor(args[1:])
	case "dnsleak":
		return runDnsleak(args[1:])
	case "swapusage":
		return runSwapusage(args[1:])
	case "loginjection":
		return runLoginjection(args[1:])
	case "certexpiry":
		return runCertexpiry(args[1:])
	case "stdinopen":
		return runStdinopen(args[1:])
	case "coredump":
		return runCoredump(args[1:])
	case "debugflag":
		return runDebugflag(args[1:])
	case "depguard":
		return runDepguard(args[1:])
	case "cmdinject":
		return runCmdinject(args[1:])
	case "proxyconfig":
		return runProxyconfig(args[1:])
	case "backupexpose":
		return runBackupexpose(args[1:])
	case "tlsconfig":
		return runTlsconfig(args[1:])
	case "corsconfig":
		return runCorsconfig(args[1:])
	case "socketbind":
		return runSocketbind(args[1:])
	case "signalforward":
		return runSignalforward(args[1:])
	case "portrange":
		return runPortrange(args[1:])
	case "gpuaccess":
		return runGpuaccess(args[1:])
	case "procexec":
		return runProcexec(args[1:])
	case "symlink":
		return runSymlink(args[1:])
	case "bindmount":
		return runBindmount(args[1:])
	case "nsenter":
		return runNsenter(args[1:])
	case "auditlog":
		return runAuditlog(args[1:])
	case "syslog":
		return runSyslog(args[1:])
	case "dbus":
		return runDbus(args[1:])
	case "pipeclean":
		return runPipeclean(args[1:])
	case "ambient":
		return runAmbient(args[1:])
	case "securityopt":
		return runSecurityopt(args[1:])
	case "affinity":
		return runAffinity(args[1:])
	case "linklocal":
		return runLinklocal(args[1:])
	case "netalias":
		return runNetalias(args[1:])
	case "extnet":
		return runExtnet(args[1:])
	case "cgroupescape":
		return runCgroupescape(args[1:])
	case "timesync":
		return runTimesync(args[1:])
	case "vxlan":
		return runVxlan(args[1:])
	case "macvlan":
		return runMacvlan(args[1:])
	case "bridgeaudit":
		return runBridgeaudit(args[1:])
	case "mcastaudit":
		return runMcastaudit(args[1:])
	case "proxyproto":
		return runProxyproto(args[1:])
	case "dnstls":
		return runDnstls(args[1:])
	case "grpcaudit":
		return runGrpcaudit(args[1:])
	case "tlsversion":
		return runTlsversion(args[1:])
	case "webhooksec":
		return runWebhooksec(args[1:])
	case "jwtsec":
		return runJwtsec(args[1:])
	case "ssrfaudit":
		return runSsrfaudit(args[1:])
	case "headerinjection":
		return runHeaderinjection(args[1:])
	case "sigverify":
		return runSigverify(args[1:])
	case "execguard":
		return runExecguard(args[1:])
	case "overlayfs":
		return runOverlayfs(args[1:])
	case "nonroot":
		return runNonroot(args[1:])
	case "execform":
		return runExecform(args[1:])
	case "copyaudit":
		return runCopyaudit(args[1:])
	case "ldapaudit":
		return runLdapaudit(args[1:])
	case "smtpaudit":
		return runSmtpaudit(args[1:])
	case "hcprobe":
		return runHcprobe(args[1:])
	case "xmlinjection":
		return runXmlinjection(args[1:])
	case "deserializationaudit":
		return runDeserializationaudit(args[1:])
	case "deporder":
		return runDeporder(args[1:])
	case "kafkaaudit":
		return runKafkaaudit(args[1:])
	case "elasticaudit":
		return runElasticaudit(args[1:])
	case "graphqlaudit":
		return runGraphqlaudit(args[1:])
	case "mqttaudit":
		return runMqttaudit(args[1:])
	case "redisaudit":
		return runRedisaudit(args[1:])
	case "mongoaudit":
		return runMongoaudit(args[1:])
	case "rabbitmqaudit":
		return runRabbitmqaudit(args[1:])
	case "postgresaudit":
		return runPostgresaudit(args[1:])
	case "mysqlaudit":
		return runMysqlaudit(args[1:])
	case "ftpaudit":
		return runFtpaudit(args[1:])
	case "sshaudit":
		return runSshaudit(args[1:])
	case "dnssecaudit":
		return runDnssecaudit(args[1:])
	case "nfsaudit":
		return runNfsaudit(args[1:])
	case "memcachedaudit":
		return runMemcachedaudit(args[1:])
	case "etcdaudit":
		return runEtcdaudit(args[1:])
	case "snmpaudit":
		return runSnmpaudit(args[1:])
	case "sambaaudit":
		return runSambaaudit(args[1:])
	case "consulaudit":
		return runConsulaudit(args[1:])
	case "zookeeperaudit":
		return runZookeeperaudit(args[1:])
	case "cephaudit":
		return runCephaudit(args[1:])
	case "cassandraaudit":
		return runCassandraaudit(args[1:])
	case "influxdbaudit":
		return runInfluxdbaudit(args[1:])
	case "neo4jaudit":
		return runNeo4jaudit(args[1:])
	case "nomadaudit":
		return runNomadaudit(args[1:])
	case "clickhouseaudit":
		return runClickhouseaudit(args[1:])
	case "cockroachdbaudit":
		return runCockroachdbaudit(args[1:])
	case "vpnaudit":
		return runVpnaudit(args[1:])
	case "env-template", "envtemplate":
		return runEnvtemplate(args[1:])
	case "trust-chain", "trustchain":
		return runTrustchain(args[1:])
	case "completions", "completion":
		return runCompletions(args[1:])
	case "grafanaaudit":
		return runGrafanaaudit(args[1:])
	case "prometheusaudit":
		return runPrometheusaudit(args[1:])
	case "version", "--version", "-v":
		fmt.Printf("tasia %s (commit %s, built %s)\n", versionString(), Commit, Date)
		return nil
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		printUsage()
		return fmt.Errorf("unknown command")
	}
}

// validateFailOn rejects unknown severity thresholds. An unknown value ranks
// below every real severity, so a typo such as "hgih" would otherwise silently
// turn the gate into "block on any finding". An empty value means "use the
// command default".
func validateFailOn(v string) error {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "critical", "high", "medium", "low":
		return nil
	}
	return fmt.Errorf("invalid --fail-on %q (want critical, high, medium or low)", v)
}

func printUsage() {
	fmt.Println(`Tasia — private AI stack hardening gate

Usage:
  tasia diff --base DIR --current DIR [--format text|json] [--fail-on critical|high|medium|low]
  tasia review [--path .] [--format text|json|sarif] [--fail-on critical|high|medium|low] [--no-write] [--strict] [--recursive]
  tasia check [--path .] [--fail-on critical|high|medium|low] [--format text|json] [--recursive]
  tasia ci [--path .] [--fail-on critical|high|medium|low] [--recursive]
  tasia fix [--path .] [--format text|json] [--recursive]
  tasia install --pre-push
  tasia uninstall --pre-push
  tasia explain [--path .] [--ollama llama3.1] [--ollama-host localhost:11434]
  tasia rules [--format text|json]
  tasia init [--path .]
  tasia watch [--path .] [--interval 2s] [--fail-on critical|high|medium|low]
  tasia profile [--path .] [--format text|json] [--recursive]
  tasia report [--path .] [--output tasia-report.html] [--title TEXT] [--recursive]
  tasia compare --paths DIR,DIR[,DIR,...] [--format text|json]
  tasia export [--path .] [--format csv|markdown|junit] [--output FILE] [--recursive]
  tasia validate [--path .] [--format text|json]
  tasia fmt [--path .tasiarc.yaml] [--check] [--diff]
  tasia migrate [--path .tasiarc.yaml] [--dry-run]
  tasia baseline create --path DIR --output FILE
  tasia baseline compare --baseline FILE --path DIR [--format text|json]
  tasia baseline update --baseline FILE --path DIR
  tasia severity [--path .] [--format text|json] [--recursive] [--baseline FILE]
  tasia inventory [--path .] [--format text|json] [--recursive]
  tasia graph [--path .] [--format text|dot|mermaid] [--recursive]
  tasia lint [--path .] [--format text|json]
  tasia doctor [--path .] [--format text|json]
  tasia bench [--path .] [--iterations 5] [--format text|json]
  tasia benchmark-rules [--path .] [--iterations 3] [--format text|json] [--recursive]
  tasia scan [--path .] [--files FILE,...] [--rules ID,...] [--format text|json] [--fail-on critical|high|medium|low]
  tasia ignore [list|add|remove] [--path .] [--pattern PATTERN] [--format text|json]
  tasia suggest [--path .] [--severity LEVEL] [--format text|json]
  tasia history [list|record|clear] [--path .] [--last N] [--format text|json]
  tasia metrics --dir DIR [--format text|json]
  tasia tags [list|add|remove] [--path .] [--rule RULE] [--tag TAG] [--note TEXT]
  tasia compliance [--path .] [--framework all|SOC2|NIST-AI-RMF|OWASP-LLM-Top10] [--format text|json] [--recursive]
  tasia coverage [--path .] [--format text|json] [--recursive]
  tasia policy [--path .] [--format text|json|markdown] [--output FILE] [--title TEXT] [--recursive]
  tasia audit-trail [record|show|latest] [--path .] [--trail FILE] [--format text|json]
  tasia api [--path .] [--port 8080] [--recursive] [--cors-origin *]
  tasia config-check [--path .] [--format text|json] [--recursive] [--fail-on high|medium|low]
  tasia merge-check [--path .] [--format text|json] [--recursive]
  tasia port-map [--path .] [--format text|json] [--recursive]
  tasia capabilities [--path .] [--format text|json] [--recursive]
  tasia entropy [--path .] [--format text|json] [--threshold 3.5] [--recursive]
  tasia isolation [--path .] [--format text|json] [--recursive]
  tasia volumes [--path .] [--format text|json] [--recursive]
  tasia healthcheck [--path .] [--format text|json] [--recursive]
  tasia logging [--path .] [--format text|json] [--recursive]
  tasia resource-limits [--path .] [--format text|json] [--recursive]
  tasia tmpfs [--path .] [--format text|json] [--recursive]
  tasia dns [--path .] [--format text|json] [--recursive]
  tasia labels [--path .] [--format text|json] [--recursive]
  tasia net-audit [--path .] [--format text|json] [--recursive]
  tasia init-process [--path .] [--format text|json] [--recursive]
  tasia privileged [--path .] [--format text|json] [--recursive]
  tasia workload [--path .] [--format text|json] [--recursive]
  tasia image-trust [--path .] [--format text|json] [--recursive]
  tasia service-map [--path .] [--format text|json|dot] [--recursive]
  tasia image-age [--path .] [--format text|json] [--recursive]
  tasia multi-stage [--path .] [--format text|json] [--recursive]
  tasia build-cache [--path .] [--format text|json] [--recursive]
  tasia compose-validate [--path .] [--format text|json] [--recursive]
  tasia port-conflict [--path .] [--format text|json] [--recursive]
  tasia volume-audit [--path .] [--format text|json] [--recursive]
  tasia net-analyze [--path .] [--format text|json] [--recursive]
  tasia rate-limit [--path .] [--format text|json] [--recursive]
  tasia blkio [--path .] [--format text|json] [--recursive]
  tasia bind-prop [--path .] [--format text|json] [--recursive]
  tasia completions --shell bash|zsh|fish
  tasia schema
  tasia version
  tasia help

Review local/private AI deployment configs, block risky patterns, generate hardening pack.`)
}

func runReview(args []string) error {
	fs := flag.NewFlagSet("review", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "text", "output format: text, json or sarif")
	failOn := fs.String("fail-on", "", "fail level: critical, high, medium, low")
	noWrite := fs.Bool("no-write", false, "do not write .tasia/ artifacts")
	strict := fs.Bool("strict", false, "treat warnings as blocking too")
	verbose := fs.Bool("verbose", false, "show why/fix/evidence details for each finding")
	baselinePath := fs.String("baseline", "", "SARIF file of known findings to suppress")
	recursive := fs.Bool("recursive", false, "scan nested directories in monorepos")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateFailOn(*failOn); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	t0 := time.Now()

	var findings []rules.Finding
	var collected *collect.Collected
	if *recursive {
		findings = scanRecursive(absPath)
	} else {
		// Collect
		var err error
		collected, err = collect.WalkAndCollect(absPath)
		if err != nil {
			return err
		}

		// Fail closed: an unparseable config cannot be vouched for. Report ERROR,
		// write nothing, and exit 2 rather than a misleading PASS.
		if len(collected.ParseErrors) > 0 {
			switch *format {
			case "json":
				fmt.Println(report.ErrorJSON(collected.ParseErrors))
			case "sarif":
				out, _ := report.FindingsToSARIF(nil, versionString())
				fmt.Println(out)
			default:
				report.PrintErrorVerdict(collected.ParseErrors)
			}
			os.Exit(2)
		}

		// Rules
		findings = rules.Evaluate(collected)

		// Apply .tasiaignore and inline tasia:disable suppressions
		if pol, err := ignore.Load(absPath); err == nil {
			pol.AddInline(ignore.ScanInline(absPath))
			findings = filterFindings(findings, pol)
		}

		// Apply severity overrides from .tasiarc.yaml
		if cfg, err := config.Load(absPath); err == nil {
			findings = applySeverityOverrides(findings, cfg)
		}
	}

	// Apply SARIF baseline filtering
	if *baselinePath != "" {
		baseline, err := report.LoadBaseline(*baselinePath)
		if err != nil {
			return fmt.Errorf("loading baseline: %w", err)
		}
		findings, _ = report.FilterBaseline(findings, baseline)
	}

	// Decide
	decision, risk := report.Decide(findings, *failOn, *strict)

	durationMs := time.Since(t0).Milliseconds()

	// In recursive mode collected is nil; build summary from findings count.
	var filesScanned int
	if collected != nil {
		filesScanned = collected.FilesScanned()
	}
	summary := report.BuildSummary(findings, filesScanned, durationMs)

	// Write unless no-write (do this first so side-effects don't affect format)
	wrotePath := ""
	if !*noWrite && collected != nil {
		outDir := filepath.Join(absPath, ".tasia")
		if err := os.MkdirAll(outDir, 0755); err != nil {
			return err
		}
		if err := report.WriteArtifacts(outDir, collected, findings, decision, risk); err != nil {
			return err
		}
		wrotePath = outDir
	}

	// Terminal (json/sarif must be pure on stdout)
	switch *format {
	case "json":
		out, _ := report.FindingsToJSON(findings, decision, risk, &summary)
		fmt.Println(out)
		if wrotePath != "" {
			fmt.Fprintf(os.Stderr, "Wrote .tasia/ hardening pack to %s\n", wrotePath)
		}
	case "sarif":
		out, _ := report.FindingsToSARIF(findings, versionString())
		fmt.Println(out)
		if wrotePath != "" {
			fmt.Fprintf(os.Stderr, "Wrote .tasia/ hardening pack to %s\n", wrotePath)
		}
	default:
		if *verbose {
			report.PrintVerboseSummary(findings, decision, risk)
		} else {
			report.PrintSummary(findings, decision, risk)
		}
		if wrotePath != "" {
			fmt.Printf("\nWrote .tasia/ hardening pack to %s\n", wrotePath)
		}
	}

	exitCode := 0
	if decision == "BLOCKED" {
		exitCode = 1
	}
	fmt.Fprintln(os.Stderr, report.ExitSummaryLine(findings, exitCode))

	return nil
}

func runCI(args []string) error {
	fs := flag.NewFlagSet("ci", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	failOn := fs.String("fail-on", "high", "fail level: critical, high, medium, low")
	baselinePath := fs.String("baseline", "", "SARIF file of known findings to suppress")
	verbose := fs.Bool("verbose", false, "show why/fix/evidence details for each finding")
	recursive := fs.Bool("recursive", false, "scan nested directories in monorepos")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateFailOn(*failOn); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	var findings []rules.Finding
	if *recursive {
		findings = scanRecursive(absPath)
	} else {
		collected, err := collect.WalkAndCollect(absPath)
		if err != nil {
			return err
		}

		// Fail closed on unparseable config: a gate must not pass what it can't read.
		if len(collected.ParseErrors) > 0 {
			report.PrintErrorVerdict(collected.ParseErrors)
			fmt.Fprintln(os.Stderr, "CI error: unparseable config; failing closed")
			os.Exit(2)
		}

		findings = rules.Evaluate(collected)

		if pol, err := ignore.Load(absPath); err == nil {
			pol.AddInline(ignore.ScanInline(absPath))
			findings = filterFindings(findings, pol)
		}

		if cfg, err := config.Load(absPath); err == nil {
			findings = applySeverityOverrides(findings, cfg)
		}
	}

	if *baselinePath != "" {
		bl, err := report.LoadBaseline(*baselinePath)
		if err != nil {
			return fmt.Errorf("loading baseline: %w", err)
		}
		findings, _ = report.FilterBaseline(findings, bl)
	}

	decision, risk := report.Decide(findings, *failOn, false)

	if *verbose {
		report.PrintVerboseSummary(findings, decision, risk)
	} else {
		report.PrintSummary(findings, decision, risk)
	}

	if decision == "BLOCKED" {
		fmt.Fprintln(os.Stderr, report.ExitSummaryLine(findings, 1))
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, report.ExitSummaryLine(findings, 0))
	return nil
}

func runInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	prePush := fs.Bool("pre-push", false, "install pre-push git hook")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*prePush {
		fmt.Println("usage: tasia install --pre-push")
		return nil
	}

	gitRoot, err := findGitRoot()
	if err != nil {
		return err
	}
	hookDir := filepath.Join(gitRoot, ".git", "hooks")
	if err := os.MkdirAll(hookDir, 0755); err != nil {
		return err
	}
	hookPath := filepath.Join(hookDir, "pre-push")

	const marker = "# Installed by tasia install --pre-push"

	// Never silently clobber a pre-existing, non-tasia hook (e.g. husky).
	if existing, err := os.ReadFile(hookPath); err == nil && !strings.Contains(string(existing), marker) {
		fmt.Fprintf(os.Stderr, "A pre-push hook already exists at %s and was not installed by tasia.\n", hookPath)
		fmt.Fprintln(os.Stderr, "Refusing to overwrite it. To add tasia, append this line to that hook:")
		fmt.Fprintln(os.Stderr, "  command -v tasia >/dev/null 2>&1 && tasia ci --path . --fail-on high")
		return fmt.Errorf("existing pre-push hook not overwritten")
	}

	// Resolve tasia from PATH at hook-run time so the hook keeps working if the
	// binary is upgraded or moved. Fail closed (block the push) if it is missing.
	hookContent := "#!/bin/sh\n" +
		marker + "\n" +
		"if ! command -v tasia >/dev/null 2>&1; then\n" +
		"  echo \"tasia not found in PATH — install it or run: tasia uninstall --pre-push\" >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"tasia ci --path . --fail-on high || exit 1\n"

	if err := os.WriteFile(hookPath, []byte(hookContent), 0755); err != nil {
		return err
	}
	fmt.Printf("Installed pre-push hook at %s\n", hookPath)
	fmt.Println("It will run: tasia ci --path . --fail-on high (tasia resolved from PATH)")
	return nil
}

func runUninstall(args []string) error {
	// Support tasia uninstall --pre-push
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	prePush := fs.Bool("pre-push", false, "remove pre-push git hook")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*prePush {
		fmt.Println("usage: tasia uninstall --pre-push")
		return nil
	}
	gitRoot, err := findGitRoot()
	if err != nil {
		return err
	}
	hookPath := filepath.Join(gitRoot, ".git", "hooks", "pre-push")
	if _, err := os.Stat(hookPath); os.IsNotExist(err) {
		fmt.Println("No pre-push hook to remove.")
		return nil
	}
	if err := os.Remove(hookPath); err != nil {
		return err
	}
	fmt.Printf("Removed %s\n", hookPath)
	return nil
}

// findGitRoot walks upward from cwd to locate the directory containing .git
func findGitRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if st, err := os.Stat(filepath.Join(dir, ".git")); err == nil && st.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir || parent == "" {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("no .git directory found (run from inside a git repo)")
}

func runExplain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	ollama := fs.String("ollama", "", "ollama model name for local explanation (e.g. llama3.1)")
	ollamaHost := fs.String("ollama-host", llm.DefaultOllamaHost, "host[:port] of local Ollama")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}
	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}
	// Fail closed: don't send an incomplete picture to the model.
	if len(collected.ParseErrors) > 0 {
		report.PrintErrorVerdict(collected.ParseErrors)
		os.Exit(2)
	}
	findings := rules.Evaluate(collected)

	if pol, err := ignore.Load(absPath); err == nil {
		pol.AddInline(ignore.ScanInline(absPath))
		findings = filterFindings(findings, pol)
	}

	if cfg, err := config.Load(absPath); err == nil {
		findings = applySeverityOverrides(findings, cfg)
	}

	decision, risk := report.Decide(findings, "high", false)

	redacted := llm.RedactPack(decision, risk, findings)

	outDir := filepath.Join(absPath, ".tasia")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}

	// Without a model we cannot call Ollama. Write the redacted facts and the
	// exact command to populate prose. This never fails and never transmits.
	if *ollama == "" {
		review := "# LLM_REVIEW.md\n\n" +
			"Deterministic rule findings are the source of truth. This file is optional prose only.\n\n" +
			"Run with `--ollama <model>` to generate a human-readable summary from the redacted facts below:\n\n" +
			"    tasia explain --ollama llama3.1\n\n" +
			"## Redacted facts sent to the local model\n\n" +
			"```json\n" + redacted + "\n```\n"
		if err := os.WriteFile(filepath.Join(outDir, "LLM_REVIEW.md"), []byte(review), 0644); err != nil {
			return err
		}
		fmt.Printf("Wrote redacted facts to %s (no model called; pass --ollama <model> for prose).\n", filepath.Join(outDir, "LLM_REVIEW.md"))
		return nil
	}

	// Real call: send ONLY the redacted pack to the local Ollama.
	client := llm.NewOllamaClient(*ollamaHost)
	fmt.Printf("Sending redacted findings (decision=%s risk=%s, %d findings) to local model %q at %s ...\n",
		decision, risk, len(findings), *ollama, client.Host)

	prose, err := client.Explain(*ollama, decision, risk, findings)
	if err != nil {
		// LLM problems are tool/config errors (exit 2), never a review failure.
		return fmt.Errorf("local LLM explanation failed (deterministic findings are unaffected): %v\n"+
			"Is Ollama running? Try: ollama serve  and  ollama pull %s", err, *ollama)
	}

	review := "# LLM_REVIEW.md\n\n" +
		"> Generated by a local Ollama model (`" + *ollama + "`) from redacted facts only.\n" +
		"> Deterministic rule findings remain the source of truth; this prose is advisory.\n\n" +
		"## Summary\n\n" + prose + "\n\n" +
		"## Redacted facts provided to the model\n\n" +
		"```json\n" + redacted + "\n```\n"
	if err := os.WriteFile(filepath.Join(outDir, "LLM_REVIEW.md"), []byte(review), 0644); err != nil {
		return err
	}
	fmt.Printf("Wrote %s\n", filepath.Join(outDir, "LLM_REVIEW.md"))
	return nil
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

func applySeverityOverrides(findings []rules.Finding, cfg *config.Config) []rules.Finding {
	out := make([]rules.Finding, len(findings))
	copy(out, findings)
	for i := range out {
		if override := cfg.SeverityFor(out[i].ID); override != "" && config.ValidSeverity(override) {
			out[i].Severity = rules.Severity(override)
		}
	}
	return out
}

func runRules(args []string) error {
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}

	catalog := rules.Catalog()

	switch *format {
	case "json":
		data, err := json.MarshalIndent(catalog, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	default:
		lastCat := ""
		for _, r := range catalog {
			if r.Category != lastCat {
				if lastCat != "" {
					fmt.Println()
				}
				fmt.Printf("── %s ──\n", r.Category)
				lastCat = r.Category
			}
			fmt.Printf("  %-10s %-30s %s\n", r.Default, r.ID, r.Title)
		}
		fmt.Printf("\n%d rules total\n", len(catalog))
	}
	return nil
}

func runDiff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	basePath := fs.String("base", "", "path to baseline scan directory (required)")
	curPath := fs.String("current", "", "path to current scan directory (required)")
	format := fs.String("format", "text", "output format: text or json")
	failOn := fs.String("fail-on", "", "exit 1 if any new finding at or above this severity")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *basePath == "" || *curPath == "" {
		fmt.Fprintln(os.Stderr, "tasia diff: --base and --current are required")
		fs.Usage()
		return fmt.Errorf("missing required flags")
	}
	if err := validateFailOn(*failOn); err != nil {
		return err
	}

	baseFindings := scanDir(*basePath)
	curFindings := scanDir(*curPath)

	baseDec, _ := report.Decide(baseFindings, "high", false)
	curDec, _ := report.Decide(curFindings, "high", false)

	diff := report.DiffFindings(baseFindings, curFindings)
	diff.BaseDecision = baseDec
	diff.CurrentDecision = curDec

	switch *format {
	case "json":
		out, err := report.DiffToJSON(diff)
		if err != nil {
			return err
		}
		fmt.Println(out)
	default:
		fmt.Print(report.DiffToText(diff))
	}

	if *failOn != "" {
		threshold := rules.Severity(strings.ToUpper(*failOn))
		for _, f := range diff.New {
			if f.Severity.Rank() >= threshold.Rank() {
				fmt.Fprintf(os.Stderr, "tasia diff: new finding at or above %s\n", threshold)
				os.Exit(1)
			}
		}
	}
	return nil
}

func scanDir(path string) []rules.Finding {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil
	}
	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return nil
	}
	if len(collected.ParseErrors) > 0 {
		return nil
	}
	findings := rules.Evaluate(collected)
	if pol, err := ignore.Load(absPath); err == nil {
		pol.AddInline(ignore.ScanInline(absPath))
		findings = filterFindings(findings, pol)
	}
	if cfg, err := config.Load(absPath); err == nil {
		findings = applySeverityOverrides(findings, cfg)
	}
	return findings
}

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	path := fs.String("path", ".", "directory to initialise")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	rcPath := filepath.Join(absPath, ".tasiarc.yaml")
	if _, err := os.Stat(rcPath); err == nil {
		return fmt.Errorf("%s already exists; remove it first to reinitialise", rcPath)
	}

	ignorePath := filepath.Join(absPath, ".tasiaignore")
	if _, err := os.Stat(ignorePath); err == nil {
		return fmt.Errorf("%s already exists; remove it first to reinitialise", ignorePath)
	}

	rcContent := generateConfig()
	if err := os.WriteFile(rcPath, []byte(rcContent), 0o644); err != nil {
		return err
	}

	ignoreContent := generateIgnore()
	if err := os.WriteFile(ignorePath, []byte(ignoreContent), 0o644); err != nil {
		return err
	}

	fmt.Printf("Created %s\n", rcPath)
	fmt.Printf("Created %s\n", ignorePath)
	return nil
}

func generateConfig() string {
	var b strings.Builder
	b.WriteString("# tasia configuration — severity overrides\n")
	b.WriteString("# Uncomment and change a severity to override the default.\n")
	b.WriteString("# Valid values: critical, high, medium, low\n")
	b.WriteString("#\n")
	b.WriteString("# See: tasia rules --format text\n\n")
	b.WriteString("severities:\n")

	cat := rules.Catalog()
	currentCategory := ""
	for _, r := range cat {
		if r.Category != currentCategory {
			currentCategory = r.Category
			b.WriteString(fmt.Sprintf("\n  # --- %s ---\n", currentCategory))
		}
		b.WriteString(fmt.Sprintf("  # %s: %s\n", r.ID, strings.ToLower(string(r.Default))))
	}
	return b.String()
}

func generateIgnore() string {
	var b strings.Builder
	b.WriteString("# tasia ignore patterns — one glob per line\n")
	b.WriteString("# Lines starting with # are comments.\n")
	b.WriteString("# Patterns follow .gitignore syntax.\n\n")
	b.WriteString("# Common directories to skip:\n")
	b.WriteString("# node_modules/\n")
	b.WriteString("# .git/\n")
	b.WriteString("# vendor/\n")
	b.WriteString("# dist/\n")
	b.WriteString("# build/\n")
	return b.String()
}

func runSchema(_ []string) error {
	fmt.Println(report.FindingsJSONSchema)
	return nil
}

type profileResult struct {
	Score           int                    `json:"score"`
	Grade           string                 `json:"grade"`
	TotalFindings   int                    `json:"total_findings"`
	BySeverity      map[string]int         `json:"by_severity"`
	ByCategory      map[string]int         `json:"by_category"`
	TopIssues       []profileIssue         `json:"top_issues"`
	Recommendations []string               `json:"recommendations"`
}

type profileIssue struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Count    int    `json:"count"`
}

func runProfile(args []string) error {
	fs := flag.NewFlagSet("profile", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "text", "output format: text or json")
	recursive := fs.Bool("recursive", false, "scan nested directories")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	var findings []rules.Finding
	if *recursive {
		findings = scanRecursive(absPath)
	} else {
		findings = scanDir(absPath)
	}

	result := buildProfile(findings)

	switch *format {
	case "json":
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	default:
		printProfile(result)
	}
	return nil
}

func buildProfile(findings []rules.Finding) profileResult {
	bySeverity := map[string]int{}
	byCategory := map[string]int{}
	issueCount := map[string]int{}
	issueInfo := map[string]rules.Finding{}

	for _, f := range findings {
		sev := string(f.Severity)
		bySeverity[sev]++

		cat := categoryFromID(f.ID)
		byCategory[cat]++

		issueCount[f.ID]++
		if _, exists := issueInfo[f.ID]; !exists {
			issueInfo[f.ID] = f
		}
	}

	score := computeScore(bySeverity)
	grade := scoreToGrade(score)

	var topIssues []profileIssue
	for id, count := range issueCount {
		f := issueInfo[id]
		topIssues = append(topIssues, profileIssue{
			ID:       id,
			Severity: string(f.Severity),
			Title:    f.Title,
			Count:    count,
		})
	}
	sortProfileIssues(topIssues)
	if len(topIssues) > 5 {
		topIssues = topIssues[:5]
	}

	recommendations := buildRecommendations(bySeverity, byCategory)

	return profileResult{
		Score:           score,
		Grade:           grade,
		TotalFindings:   len(findings),
		BySeverity:      bySeverity,
		ByCategory:      byCategory,
		TopIssues:       topIssues,
		Recommendations: recommendations,
	}
}

func computeScore(bySeverity map[string]int) int {
	score := 100
	score -= bySeverity["CRITICAL"] * 25
	score -= bySeverity["HIGH"] * 10
	score -= bySeverity["MEDIUM"] * 5
	score -= bySeverity["LOW"] * 2
	if score < 0 {
		score = 0
	}
	return score
}

func scoreToGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

func categoryFromID(id string) string {
	parts := strings.SplitN(id, "_", 2)
	if len(parts) == 0 {
		return "unknown"
	}
	prefixes := map[string]string{
		"exposed":       "compose",
		"docker":        "compose",
		"privileged":    "compose",
		"permissive":    "compose",
		"latest":        "compose",
		"broad":         "compose",
		"env":           "compose",
		"no":            "compose",
		"vector":        "compose",
		"agent":         "agent",
		"kube":          "kubernetes",
		"helm":          "helm",
		"tf":            "terraform",
		"dockerfile":    "dockerfile",
		"reverse":       "proxy",
	}
	if cat, ok := prefixes[parts[0]]; ok {
		return cat
	}
	return "other"
}

func sortProfileIssues(issues []profileIssue) {
	for i := 0; i < len(issues); i++ {
		for j := i + 1; j < len(issues); j++ {
			ri := rules.Severity(issues[i].Severity).Rank()
			rj := rules.Severity(issues[j].Severity).Rank()
			if rj > ri || (rj == ri && issues[j].Count > issues[i].Count) {
				issues[i], issues[j] = issues[j], issues[i]
			}
		}
	}
}

func buildRecommendations(bySeverity, byCategory map[string]int) []string {
	var recs []string
	if bySeverity["CRITICAL"] > 0 {
		recs = append(recs, fmt.Sprintf("Fix %d critical findings immediately — these represent direct compromise vectors", bySeverity["CRITICAL"]))
	}
	if byCategory["compose"] > 3 {
		recs = append(recs, "Review docker-compose exposure rules — multiple services are published to all interfaces")
	}
	if byCategory["terraform"] > 0 {
		recs = append(recs, "Tighten cloud infrastructure security groups and IAM policies")
	}
	if byCategory["agent"] > 0 {
		recs = append(recs, "Restrict agent runtime permissions — auto-approve and writable mounts increase blast radius")
	}
	if byCategory["kubernetes"] > 0 {
		recs = append(recs, "Apply least-privilege to Kubernetes workloads — avoid privileged containers and host networking")
	}
	if len(recs) == 0 {
		recs = append(recs, "No critical issues detected — maintain current security posture")
	}
	return recs
}

func printProfile(p profileResult) {
	fmt.Printf("Security Profile: %s (%d/100)\n", p.Grade, p.Score)
	fmt.Printf("Total findings: %d\n\n", p.TotalFindings)

	fmt.Println("By severity:")
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if count, ok := p.BySeverity[sev]; ok && count > 0 {
			fmt.Printf("  %-10s %d\n", sev, count)
		}
	}

	if len(p.ByCategory) > 0 {
		fmt.Println("\nBy category:")
		for cat, count := range p.ByCategory {
			fmt.Printf("  %-15s %d\n", cat, count)
		}
	}

	if len(p.TopIssues) > 0 {
		fmt.Println("\nTop issues:")
		for _, issue := range p.TopIssues {
			fmt.Printf("  [%s] %s (%dx)\n", issue.Severity, issue.Title, issue.Count)
		}
	}

	fmt.Println("\nRecommendations:")
	for _, r := range p.Recommendations {
		fmt.Printf("  - %s\n", r)
	}
}
