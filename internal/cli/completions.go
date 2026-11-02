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

    commands="review diff check ci fix export validate report compare fmt migrate inventory graph baseline severity install uninstall explain rules schema init watch profile completions version help"

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
