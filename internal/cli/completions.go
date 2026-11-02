package cli

import (
	"flag"
	"fmt"
	"os"
)

const bashCompletion = `_tasia() {
    local cur prev commands
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    commands="review diff check ci fix export validate report compare fmt migrate inventory graph baseline severity lint doctor install uninstall explain rules schema init watch profile compliance coverage snapshot drift policy audit-trail network secrets-scan sbom risk-matrix changelog status config-test env-audit hotspots prioritize benchmark-rules api config-check merge-check port-map capabilities completions version help"

    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${commands}" -- "${cur}") )
        return 0
    fi

    case "${prev}" in
        --path|--base|--current|--baseline)
            COMPREPLY=( $(compgen -d -- "${cur}") )
            return 0
            ;;
        --fail-on)
            COMPREPLY=( $(compgen -W "critical high medium low" -- "${cur}") )
            return 0
            ;;
        --format)
            COMPREPLY=( $(compgen -W "text json sarif" -- "${cur}") )
            return 0
            ;;
        --shell)
            COMPREPLY=( $(compgen -W "bash zsh fish" -- "${cur}") )
            return 0
            ;;
        --interval)
            return 0
            ;;
    esac

    COMPREPLY=( $(compgen -W "--path --fail-on --format --verbose --baseline --recursive --no-write --strict" -- "${cur}") )
    return 0
}
complete -F _tasia tasia
`

const zshCompletion = `#compdef tasia

_tasia() {
    local -a commands
    commands=(
        'review:Review AI stack deployment configs'
        'diff:Compare two config directories'
        'check:Quick pass/fail CI check'
        'ci:CI mode with exit codes'
        'install:Install git hooks'
        'uninstall:Remove git hooks'
        'explain:AI-powered finding explanations'
        'rules:List available security rules'
        'schema:Print JSON Schema for findings'
        'init:Generate starter config'
        'watch:Watch for config changes'
        'fix:Show auto-remediation suggestions'
        'profile:Aggregate security profile'
        'report:Generate standalone HTML security report'
        'compare:Compare findings across multiple projects'
        'export:Export findings as CSV, Markdown, or JUnit XML'
        'validate:Check config files for errors'
        'fmt:Format and normalize .tasiarc.yaml'
        'migrate:Upgrade config to latest schema'
        'inventory:List stack services, ports, volumes and networks'
        'graph:Visualize service dependency graph'
        'baseline:Manage finding baselines for drift tracking'
        'severity:Analyze finding severity distribution and risk'
        'lint:Check config files for common mistakes'
        'doctor:Check environment readiness'
        'compliance:Map findings to compliance frameworks'
        'coverage:Show rule coverage report'
        'sbom:Generate software bill of materials'
        'risk-matrix:Produce severity x likelihood risk matrix'
        'snapshot:Capture security state at a point in time'
        'drift:Compare two security snapshots'
        'policy:Generate security policy document from scan results'
        'audit-trail:Manage append-only scan history log'
        'network:Analyze Docker network security topology'
        'secrets-scan:Deep secret detection across config files'
        'changelog:Auto-generate security changelog from audit trail'
        'status:Security posture dashboard with grade and metrics'
        'config-test:Validate configuration file against rule catalog'
        'env-audit:Audit environment variables across config files'
        'hotspots:Find files with the most security findings'
        'prioritize:Risk-based finding prioritization'
        'benchmark-rules:Per-category rule performance profiler'
        'api:Start REST API server for programmatic scanning'
        'config-check:Detect configuration conflicts across compose files'
        'merge-check:Simulate docker-compose merge and show overrides'
        'port-map:Visualize host port allocations across compose files'
        'capabilities:Analyze container capabilities and seccomp profiles'
        'completions:Generate shell completions'
        'version:Show version info'
        'help:Show usage'
    )

    _arguments \
        '1:command:->command' \
        '*::arg:->args'

    case $state in
        command)
            _describe 'tasia command' commands
            ;;
        args)
            case $words[1] in
                review|check|ci|explain|init|watch|profile)
                    _arguments \
                        '--path[path to scan]:directory:_directories' \
                        '--fail-on[failure threshold]:(critical high medium low)' \
                        '--format[output format]:(text json sarif)' \
                        '--verbose[show detailed output]' \
                        '--baseline[SARIF baseline file]:file:_files' \
                        '--recursive[scan nested directories]' \
                        '--no-write[skip writing report]' \
                        '--strict[strict mode]'
                    ;;
                diff)
                    _arguments \
                        '--base[base directory]:directory:_directories' \
                        '--current[current directory]:directory:_directories' \
                        '--format[output format]:(text json)' \
                        '--fail-on[failure threshold]:(critical high medium low)'
                    ;;
                completions)
                    _arguments '--shell[shell type]:(bash zsh fish)'
                    ;;
                rules)
                    _arguments '--format[output format]:(text json)'
                    ;;
                report)
                    _arguments \
                        '--path[path to scan]:directory:_directories' \
                        '--output[output file]:file:_files' \
                        '--title[report title]' \
                        '--recursive[scan nested directories]'
                    ;;
                compare)
                    _arguments \
                        '--paths[comma-separated directories]' \
                        '--format[output format]:(text json)'
                    ;;
                export)
                    _arguments \
                        '--path[path to scan]:directory:_directories' \
                        '--format[output format]:(csv markdown junit)' \
                        '--output[output file]:file:_files' \
                        '--recursive[scan nested directories]'
                    ;;
                validate)
                    _arguments \
                        '--path[directory with config files]:directory:_directories' \
                        '--format[output format]:(text json)'
                    ;;
                fmt)
                    _arguments \
                        '--path[config file]:file:_files' \
                        '--check[exit 1 if file would change]' \
                        '--diff[show what would change]'
                    ;;
                migrate)
                    _arguments \
                        '--path[config file]:file:_files' \
                        '--dry-run[show changes without writing]'
                    ;;
                inventory)
                    _arguments \
                        '--path[path to scan]:directory:_directories' \
                        '--format[output format]:(text json)' \
                        '--recursive[scan nested directories]'
                    ;;
                graph)
                    _arguments \
                        '--path[path to scan]:directory:_directories' \
                        '--format[output format]:(text dot mermaid)' \
                        '--recursive[scan nested directories]'
                    ;;
                baseline)
                    _arguments \
                        '1:subcommand:(create compare update)' \
                        '--path[path to scan]:directory:_directories' \
                        '--output[output file]:file:_files' \
                        '--baseline[baseline JSON file]:file:_files' \
                        '--format[output format]:(text json)'
                    ;;
                severity)
                    _arguments \
                        '--path[path to scan]:directory:_directories' \
                        '--format[output format]:(text json)' \
                        '--recursive[scan nested directories]' \
                        '--baseline[baseline file for trend]:file:_files'
                    ;;
                lint)
                    _arguments \
                        '--path[directory to check]:directory:_directories' \
                        '--format[output format]:(text json)'
                    ;;
                doctor)
                    _arguments \
                        '--path[directory to check]:directory:_directories' \
                        '--format[output format]:(text json)'
                    ;;
                compliance)
                    _arguments \
                        '--path[path to scan]:directory:_directories' \
                        '--format[output format]:(text json)' \
                        '--framework[compliance framework]:(all SOC2 NIST-AI-RMF OWASP-LLM-Top10)' \
                        '--recursive[scan nested directories]'
                    ;;
                coverage)
                    _arguments \
                        '--path[path to scan]:directory:_directories' \
                        '--format[output format]:(text json)' \
                        '--recursive[scan nested directories]'
                    ;;
                sbom)
                    _arguments \
                        '--path[path to scan]:directory:_directories' \
                        '--format[output format]:(text json spdx-lite)' \
                        '--output[output file]:file:_files' \
                        '--recursive[scan nested directories]'
                    ;;
                risk-matrix)
                    _arguments \
                        '--path[path to scan]:directory:_directories' \
                        '--format[output format]:(text json)' \
                        '--recursive[scan nested directories]'
                    ;;
                snapshot)
                    _arguments \
                        '--path[path to scan]:directory:_directories' \
                        '--output[output file]:file:_files' \
                        '--recursive[scan nested directories]'
                    ;;
                drift)
                    _arguments \
                        '--base[base snapshot file]:file:_files' \
                        '--current[current snapshot file]:file:_files' \
                        '--format[output format]:(text json)'
                    ;;
                benchmark-rules)
                    _arguments \
                        '--path[path to scan]:directory:_directories' \
                        '--format[output format]:(text json)' \
                        '--iterations[number of iterations]' \
                        '--recursive[scan nested directories]'
                    ;;
                changelog)
                    _arguments \
                        '--trail[audit trail file]:file:_files' \
                        '--format[output format]:(text json)' \
                        '--limit[max entries to show]'
                    ;;
                status)
                    _arguments \
                        '--path[path to scan]:directory:_directories' \
                        '--format[output format]:(text json)' \
                        '--recursive[scan nested directories]'
                    ;;
                config-test)
                    _arguments \
                        '--config[config file path]:file:_files' \
                        '--format[output format]:(text json)'
                    ;;
                env-audit)
                    _arguments \
                        '--path[path to scan]:directory:_directories' \
                        '--format[output format]:(text json)' \
                        '--secrets-only[show only secret-looking variables]'
                    ;;
                hotspots)
                    _arguments \
                        '--path[path to scan]:directory:_directories' \
                        '--format[output format]:(text json)' \
                        '--top[number of hotspots to show]'
                    ;;
                prioritize)
                    _arguments \
                        '--path[path to scan]:directory:_directories' \
                        '--format[output format]:(text json)' \
                        '--top[max findings to show]' \
                        '--min-score[minimum risk score]'
                    ;;
                policy)
                    _arguments \
                        '--path[path to scan]:directory:_directories' \
                        '--format[output format]:(text json markdown)' \
                        '--output[output file]:file:_files' \
                        '--title[policy document title]' \
                        '--recursive[scan nested directories]'
                    ;;
                audit-trail)
                    _arguments \
                        '1:subcommand:(record show latest)' \
                        '--path[path to scan]:directory:_directories' \
                        '--trail[audit trail file]:file:_files' \
                        '--format[output format]:(text json)' \
                        '--recursive[scan nested directories]'
                    ;;
                network)
                    _arguments \
                        '--path[path to scan]:directory:_directories' \
                        '--format[output format]:(text json dot)' \
                        '--recursive[scan nested directories]'
                    ;;
                secrets-scan)
                    _arguments \
                        '--path[path to scan]:directory:_directories' \
                        '--format[output format]:(text json)' \
                        '--recursive[scan nested directories]' \
                        '--type[filter by secret type]:(api_key password token certificate connection_string)' \
                        '--min-severity[minimum severity]:(critical high medium low)'
                    ;;
                api)
                    _arguments \
                        '--path[path to scan]:directory:_directories' \
                        '--port[HTTP listen port]' \
                        '--recursive[scan nested directories]' \
                        '--cors-origin[CORS origin header value]'
                    ;;
                config-check)
                    _arguments \
                        '--path[path to scan]:directory:_directories' \
                        '--format[output format]:(text json)' \
                        '--recursive[scan nested directories]' \
                        '--fail-on[failure threshold]:(high medium low)'
                    ;;
                merge-check)
                    _arguments \
                        '--path[path to scan]:directory:_directories' \
                        '--format[output format]:(text json)' \
                        '--recursive[scan nested directories]'
                    ;;
                port-map)
                    _arguments \
                        '--path[path to scan]:directory:_directories' \
                        '--format[output format]:(text json)' \
                        '--recursive[scan nested directories]'
                    ;;
                capabilities)
                    _arguments \
                        '--path[path to scan]:directory:_directories' \
                        '--format[output format]:(text json)' \
                        '--recursive[scan nested directories]'
                    ;;
            esac
            ;;
    esac
}

_tasia
`

const fishCompletion = `complete -c tasia -f
complete -c tasia -n '__fish_use_subcommand' -a 'review' -d 'Review AI stack deployment configs'
complete -c tasia -n '__fish_use_subcommand' -a 'diff' -d 'Compare two config directories'
complete -c tasia -n '__fish_use_subcommand' -a 'check' -d 'Quick pass/fail CI check'
complete -c tasia -n '__fish_use_subcommand' -a 'ci' -d 'CI mode with exit codes'
complete -c tasia -n '__fish_use_subcommand' -a 'fix' -d 'Show auto-remediation suggestions'
complete -c tasia -n '__fish_use_subcommand' -a 'install' -d 'Install git hooks'
complete -c tasia -n '__fish_use_subcommand' -a 'uninstall' -d 'Remove git hooks'
complete -c tasia -n '__fish_use_subcommand' -a 'explain' -d 'AI-powered finding explanations'
complete -c tasia -n '__fish_use_subcommand' -a 'rules' -d 'List available security rules'
complete -c tasia -n '__fish_use_subcommand' -a 'schema' -d 'Print JSON Schema for findings'
complete -c tasia -n '__fish_use_subcommand' -a 'init' -d 'Generate starter config'
complete -c tasia -n '__fish_use_subcommand' -a 'watch' -d 'Watch for config changes'
complete -c tasia -n '__fish_use_subcommand' -a 'profile' -d 'Aggregate security profile'
complete -c tasia -n '__fish_use_subcommand' -a 'report' -d 'Generate standalone HTML security report'
complete -c tasia -n '__fish_use_subcommand' -a 'compare' -d 'Compare findings across multiple projects'
complete -c tasia -n '__fish_use_subcommand' -a 'export' -d 'Export findings as CSV, Markdown, or JUnit XML'
complete -c tasia -n '__fish_use_subcommand' -a 'validate' -d 'Check config files for errors'
complete -c tasia -n '__fish_use_subcommand' -a 'fmt' -d 'Format and normalize .tasiarc.yaml'
complete -c tasia -n '__fish_use_subcommand' -a 'migrate' -d 'Upgrade config to latest schema'
complete -c tasia -n '__fish_use_subcommand' -a 'inventory' -d 'List stack services, ports, volumes and networks'
complete -c tasia -n '__fish_use_subcommand' -a 'graph' -d 'Visualize service dependency graph'
complete -c tasia -n '__fish_use_subcommand' -a 'baseline' -d 'Manage finding baselines for drift tracking'
complete -c tasia -n '__fish_use_subcommand' -a 'severity' -d 'Analyze finding severity distribution and risk'
complete -c tasia -n '__fish_use_subcommand' -a 'lint' -d 'Check config files for common mistakes'
complete -c tasia -n '__fish_use_subcommand' -a 'doctor' -d 'Check environment readiness'
complete -c tasia -n '__fish_use_subcommand' -a 'compliance' -d 'Map findings to compliance frameworks'
complete -c tasia -n '__fish_use_subcommand' -a 'coverage' -d 'Show rule coverage report'
complete -c tasia -n '__fish_use_subcommand' -a 'completions' -d 'Generate shell completions'
complete -c tasia -n '__fish_use_subcommand' -a 'version' -d 'Show version info'
complete -c tasia -n '__fish_use_subcommand' -a 'help' -d 'Show usage'

complete -c tasia -n '__fish_seen_subcommand_from review check ci fix explain init watch profile' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from review check ci' -l fail-on -d 'Failure threshold' -r -a 'critical high medium low'
complete -c tasia -n '__fish_seen_subcommand_from review check' -l format -d 'Output format' -r -a 'text json sarif'
complete -c tasia -n '__fish_seen_subcommand_from review check ci' -l verbose -d 'Show detailed output'
complete -c tasia -n '__fish_seen_subcommand_from review check' -l baseline -d 'SARIF baseline file' -r -F
complete -c tasia -n '__fish_seen_subcommand_from review check ci' -l recursive -d 'Scan nested directories'
complete -c tasia -n '__fish_seen_subcommand_from diff' -l base -d 'Base directory' -r -F
complete -c tasia -n '__fish_seen_subcommand_from diff' -l current -d 'Current directory' -r -F
complete -c tasia -n '__fish_seen_subcommand_from report' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from report' -l output -d 'Output file' -r -F
complete -c tasia -n '__fish_seen_subcommand_from report' -l title -d 'Report title'
complete -c tasia -n '__fish_seen_subcommand_from report' -l recursive -d 'Scan nested directories'
complete -c tasia -n '__fish_seen_subcommand_from compare' -l paths -d 'Comma-separated directories'
complete -c tasia -n '__fish_seen_subcommand_from compare' -l format -d 'Output format' -r -a 'text json'
complete -c tasia -n '__fish_seen_subcommand_from export' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from export' -l format -d 'Output format' -r -a 'csv markdown junit'
complete -c tasia -n '__fish_seen_subcommand_from export' -l output -d 'Output file' -r -F
complete -c tasia -n '__fish_seen_subcommand_from export' -l recursive -d 'Scan nested directories'
complete -c tasia -n '__fish_seen_subcommand_from validate' -l path -d 'Directory with config files' -r -F
complete -c tasia -n '__fish_seen_subcommand_from validate' -l format -d 'Output format' -r -a 'text json'
complete -c tasia -n '__fish_seen_subcommand_from fmt' -l path -d 'Config file' -r -F
complete -c tasia -n '__fish_seen_subcommand_from fmt' -l check -d 'Exit 1 if file would change'
complete -c tasia -n '__fish_seen_subcommand_from fmt' -l diff -d 'Show what would change'
complete -c tasia -n '__fish_seen_subcommand_from migrate' -l path -d 'Config file' -r -F
complete -c tasia -n '__fish_seen_subcommand_from migrate' -l dry-run -d 'Show changes without writing'
complete -c tasia -n '__fish_seen_subcommand_from inventory' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from inventory' -l format -d 'Output format' -r -a 'text json'
complete -c tasia -n '__fish_seen_subcommand_from inventory' -l recursive -d 'Scan nested directories'
complete -c tasia -n '__fish_seen_subcommand_from graph' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from graph' -l format -d 'Output format' -r -a 'text dot mermaid'
complete -c tasia -n '__fish_seen_subcommand_from graph' -l recursive -d 'Scan nested directories'
complete -c tasia -n '__fish_seen_subcommand_from baseline' -a 'create compare update' -d 'Baseline subcommand'
complete -c tasia -n '__fish_seen_subcommand_from baseline' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from baseline' -l output -d 'Output file' -r -F
complete -c tasia -n '__fish_seen_subcommand_from baseline' -l baseline -d 'Baseline JSON file' -r -F
complete -c tasia -n '__fish_seen_subcommand_from baseline' -l format -d 'Output format' -r -a 'text json'
complete -c tasia -n '__fish_seen_subcommand_from severity' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from severity' -l format -d 'Output format' -r -a 'text json'
complete -c tasia -n '__fish_seen_subcommand_from severity' -l recursive -d 'Scan nested directories'
complete -c tasia -n '__fish_seen_subcommand_from severity' -l baseline -d 'Baseline file for trend analysis' -r -F
complete -c tasia -n '__fish_seen_subcommand_from lint' -l path -d 'Directory to check' -r -F
complete -c tasia -n '__fish_seen_subcommand_from lint' -l format -d 'Output format' -r -a 'text json'
complete -c tasia -n '__fish_seen_subcommand_from doctor' -l path -d 'Directory to check' -r -F
complete -c tasia -n '__fish_seen_subcommand_from doctor' -l format -d 'Output format' -r -a 'text json'
complete -c tasia -n '__fish_seen_subcommand_from compliance' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from compliance' -l format -d 'Output format' -r -a 'text json'
complete -c tasia -n '__fish_seen_subcommand_from compliance' -l framework -d 'Compliance framework' -r -a 'all SOC2 NIST-AI-RMF OWASP-LLM-Top10'
complete -c tasia -n '__fish_seen_subcommand_from compliance' -l recursive -d 'Scan nested directories'
complete -c tasia -n '__fish_seen_subcommand_from coverage' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from coverage' -l format -d 'Output format' -r -a 'text json'
complete -c tasia -n '__fish_seen_subcommand_from coverage' -l recursive -d 'Scan nested directories'
complete -c tasia -n '__fish_use_subcommand' -a 'sbom' -d 'Generate software bill of materials'
complete -c tasia -n '__fish_use_subcommand' -a 'risk-matrix' -d 'Produce severity x likelihood risk matrix'
complete -c tasia -n '__fish_use_subcommand' -a 'snapshot' -d 'Capture security state at a point in time'
complete -c tasia -n '__fish_use_subcommand' -a 'drift' -d 'Compare two security snapshots'
complete -c tasia -n '__fish_seen_subcommand_from sbom' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from sbom' -l format -d 'Output format' -r -a 'text json spdx-lite'
complete -c tasia -n '__fish_seen_subcommand_from sbom' -l output -d 'Output file' -r -F
complete -c tasia -n '__fish_seen_subcommand_from sbom' -l recursive -d 'Scan nested directories'
complete -c tasia -n '__fish_seen_subcommand_from risk-matrix' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from risk-matrix' -l format -d 'Output format' -r -a 'text json'
complete -c tasia -n '__fish_seen_subcommand_from risk-matrix' -l recursive -d 'Scan nested directories'
complete -c tasia -n '__fish_seen_subcommand_from snapshot' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from snapshot' -l output -d 'Output file' -r -F
complete -c tasia -n '__fish_seen_subcommand_from snapshot' -l recursive -d 'Scan nested directories'
complete -c tasia -n '__fish_seen_subcommand_from drift' -l base -d 'Base snapshot file' -r -F
complete -c tasia -n '__fish_seen_subcommand_from drift' -l current -d 'Current snapshot file' -r -F
complete -c tasia -n '__fish_seen_subcommand_from drift' -l format -d 'Output format' -r -a 'text json'
complete -c tasia -n '__fish_use_subcommand' -a 'benchmark-rules' -d 'Per-category rule performance profiler'
complete -c tasia -n '__fish_seen_subcommand_from benchmark-rules' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from benchmark-rules' -l format -d 'Output format' -r -a 'text json'
complete -c tasia -n '__fish_seen_subcommand_from benchmark-rules' -l iterations -d 'Number of iterations' -r
complete -c tasia -n '__fish_seen_subcommand_from benchmark-rules' -l recursive -d 'Scan nested directories'
complete -c tasia -n '__fish_use_subcommand' -a 'changelog' -d 'Auto-generate security changelog'
complete -c tasia -n '__fish_use_subcommand' -a 'status' -d 'Security posture dashboard'
complete -c tasia -n '__fish_seen_subcommand_from changelog' -l trail -d 'Audit trail file' -r -F
complete -c tasia -n '__fish_seen_subcommand_from changelog' -l format -d 'Output format' -r -a 'text json'
complete -c tasia -n '__fish_seen_subcommand_from changelog' -l limit -d 'Max entries to show' -r
complete -c tasia -n '__fish_seen_subcommand_from status' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from status' -l format -d 'Output format' -r -a 'text json'
complete -c tasia -n '__fish_seen_subcommand_from status' -l recursive -d 'Scan nested directories'
complete -c tasia -n '__fish_use_subcommand' -a 'config-test' -d 'Validate configuration file'
complete -c tasia -n '__fish_use_subcommand' -a 'env-audit' -d 'Audit environment variables'
complete -c tasia -n '__fish_seen_subcommand_from config-test' -l config -d 'Config file path' -r -F
complete -c tasia -n '__fish_seen_subcommand_from config-test' -l format -d 'Output format' -r -a 'text json'
complete -c tasia -n '__fish_seen_subcommand_from env-audit' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from env-audit' -l format -d 'Output format' -r -a 'text json'
complete -c tasia -n '__fish_seen_subcommand_from env-audit' -l secrets-only -d 'Show only secret-looking variables'
complete -c tasia -n '__fish_use_subcommand' -a 'hotspots' -d 'Find files with the most findings'
complete -c tasia -n '__fish_seen_subcommand_from hotspots' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from hotspots' -l format -d 'Output format' -r -a 'text json'
complete -c tasia -n '__fish_seen_subcommand_from hotspots' -l top -d 'Number of hotspots' -r
complete -c tasia -n '__fish_use_subcommand' -a 'prioritize' -d 'Risk-based finding prioritization'
complete -c tasia -n '__fish_seen_subcommand_from prioritize' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from prioritize' -l format -d 'Output format' -r -a 'text json'
complete -c tasia -n '__fish_seen_subcommand_from prioritize' -l top -d 'Max findings to show' -r
complete -c tasia -n '__fish_seen_subcommand_from prioritize' -l min-score -d 'Minimum risk score' -r
complete -c tasia -n '__fish_use_subcommand' -a 'policy' -d 'Generate security policy document'
complete -c tasia -n '__fish_use_subcommand' -a 'audit-trail' -d 'Manage append-only scan history log'
complete -c tasia -n '__fish_seen_subcommand_from policy' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from policy' -l format -d 'Output format' -r -a 'text json markdown'
complete -c tasia -n '__fish_seen_subcommand_from policy' -l output -d 'Output file' -r -F
complete -c tasia -n '__fish_seen_subcommand_from policy' -l title -d 'Policy document title'
complete -c tasia -n '__fish_seen_subcommand_from policy' -l recursive -d 'Scan nested directories'
complete -c tasia -n '__fish_seen_subcommand_from audit-trail' -a 'record show latest' -d 'Audit trail subcommand'
complete -c tasia -n '__fish_seen_subcommand_from audit-trail' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from audit-trail' -l trail -d 'Audit trail file' -r -F
complete -c tasia -n '__fish_seen_subcommand_from audit-trail' -l format -d 'Output format' -r -a 'text json'
complete -c tasia -n '__fish_seen_subcommand_from audit-trail' -l recursive -d 'Scan nested directories'
complete -c tasia -n '__fish_use_subcommand' -a 'network' -d 'Analyze Docker network security topology'
complete -c tasia -n '__fish_use_subcommand' -a 'secrets-scan' -d 'Deep secret detection across config files'
complete -c tasia -n '__fish_seen_subcommand_from network' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from network' -l format -d 'Output format' -r -a 'text json dot'
complete -c tasia -n '__fish_seen_subcommand_from network' -l recursive -d 'Scan nested directories'
complete -c tasia -n '__fish_seen_subcommand_from secrets-scan' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from secrets-scan' -l format -d 'Output format' -r -a 'text json'
complete -c tasia -n '__fish_seen_subcommand_from secrets-scan' -l recursive -d 'Scan nested directories'
complete -c tasia -n '__fish_seen_subcommand_from secrets-scan' -l type -d 'Filter by secret type' -r -a 'api_key password token certificate connection_string'
complete -c tasia -n '__fish_seen_subcommand_from secrets-scan' -l min-severity -d 'Minimum severity' -r -a 'critical high medium low'
complete -c tasia -n '__fish_use_subcommand' -a 'merge-check' -d 'Simulate docker-compose merge and show overrides'
complete -c tasia -n '__fish_seen_subcommand_from merge-check' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from merge-check' -l format -d 'Output format' -r -a 'text json'
complete -c tasia -n '__fish_seen_subcommand_from merge-check' -l recursive -d 'Scan nested directories'
complete -c tasia -n '__fish_use_subcommand' -a 'port-map' -d 'Visualize host port allocations'
complete -c tasia -n '__fish_seen_subcommand_from port-map' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from port-map' -l format -d 'Output format' -r -a 'text json'
complete -c tasia -n '__fish_seen_subcommand_from port-map' -l recursive -d 'Scan nested directories'
complete -c tasia -n '__fish_use_subcommand' -a 'capabilities' -d 'Analyze container capabilities and seccomp profiles'
complete -c tasia -n '__fish_seen_subcommand_from capabilities' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from capabilities' -l format -d 'Output format' -r -a 'text json'
complete -c tasia -n '__fish_seen_subcommand_from capabilities' -l recursive -d 'Scan nested directories'
complete -c tasia -n '__fish_use_subcommand' -a 'api' -d 'Start REST API server for programmatic scanning'
complete -c tasia -n '__fish_seen_subcommand_from api' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from api' -l port -d 'HTTP listen port' -r
complete -c tasia -n '__fish_seen_subcommand_from api' -l recursive -d 'Scan nested directories'
complete -c tasia -n '__fish_seen_subcommand_from api' -l cors-origin -d 'CORS origin header value'
complete -c tasia -n '__fish_use_subcommand' -a 'config-check' -d 'Detect configuration conflicts across compose files'
complete -c tasia -n '__fish_seen_subcommand_from config-check' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from config-check' -l format -d 'Output format' -r -a 'text json'
complete -c tasia -n '__fish_seen_subcommand_from config-check' -l recursive -d 'Scan nested directories'
complete -c tasia -n '__fish_seen_subcommand_from config-check' -l fail-on -d 'Failure threshold' -r -a 'high medium low'
complete -c tasia -n '__fish_seen_subcommand_from completions' -l shell -d 'Shell type' -r -a 'bash zsh fish'
`

func runCompletions(args []string) error {
	fs := flag.NewFlagSet("completions", flag.ContinueOnError)
	shell := fs.String("shell", "", "shell type: bash, zsh, or fish")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch *shell {
	case "bash":
		fmt.Print(bashCompletion)
	case "zsh":
		fmt.Print(zshCompletion)
	case "fish":
		fmt.Print(fishCompletion)
	case "":
		fmt.Fprintln(os.Stderr, "tasia completions: --shell is required (bash, zsh, or fish)")
		return fmt.Errorf("--shell is required")
	default:
		fmt.Fprintf(os.Stderr, "tasia completions: unsupported shell %q\n", *shell)
		return fmt.Errorf("unsupported shell: %s", *shell)
	}
	return nil
}
