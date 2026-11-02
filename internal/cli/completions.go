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

    commands="review diff check ci install uninstall explain rules schema init watch profile completions version help"

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
        'profile:Aggregate security profile'
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
complete -c tasia -n '__fish_use_subcommand' -a 'install' -d 'Install git hooks'
complete -c tasia -n '__fish_use_subcommand' -a 'uninstall' -d 'Remove git hooks'
complete -c tasia -n '__fish_use_subcommand' -a 'explain' -d 'AI-powered finding explanations'
complete -c tasia -n '__fish_use_subcommand' -a 'rules' -d 'List available security rules'
complete -c tasia -n '__fish_use_subcommand' -a 'schema' -d 'Print JSON Schema for findings'
complete -c tasia -n '__fish_use_subcommand' -a 'init' -d 'Generate starter config'
complete -c tasia -n '__fish_use_subcommand' -a 'watch' -d 'Watch for config changes'
complete -c tasia -n '__fish_use_subcommand' -a 'profile' -d 'Aggregate security profile'
complete -c tasia -n '__fish_use_subcommand' -a 'completions' -d 'Generate shell completions'
complete -c tasia -n '__fish_use_subcommand' -a 'version' -d 'Show version info'
complete -c tasia -n '__fish_use_subcommand' -a 'help' -d 'Show usage'

complete -c tasia -n '__fish_seen_subcommand_from review check ci explain init watch profile' -l path -d 'Path to scan' -r -F
complete -c tasia -n '__fish_seen_subcommand_from review check ci' -l fail-on -d 'Failure threshold' -r -a 'critical high medium low'
complete -c tasia -n '__fish_seen_subcommand_from review check' -l format -d 'Output format' -r -a 'text json sarif'
complete -c tasia -n '__fish_seen_subcommand_from review check ci' -l verbose -d 'Show detailed output'
complete -c tasia -n '__fish_seen_subcommand_from review check' -l baseline -d 'SARIF baseline file' -r -F
complete -c tasia -n '__fish_seen_subcommand_from review check ci' -l recursive -d 'Scan nested directories'
complete -c tasia -n '__fish_seen_subcommand_from diff' -l base -d 'Base directory' -r -F
complete -c tasia -n '__fish_seen_subcommand_from diff' -l current -d 'Current directory' -r -F
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
