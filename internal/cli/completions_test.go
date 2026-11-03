package cli

import (
	"os"
	"strings"
	"testing"
)

func TestCompletionsBash(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := Run([]string{"completions", "--shell", "bash"})
	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("bash completions error: %v", err)
	}
	buf := make([]byte, 8192)
	n, _ := r.Read(buf)
	output := string(buf[:n])
	if !strings.Contains(output, "_tasia") {
		t.Error("bash output should contain _tasia function")
	}
	if !strings.Contains(output, "complete -F _tasia tasia") {
		t.Error("bash output should register the completion")
	}
}

func TestCompletionsZsh(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := Run([]string{"completions", "--shell", "zsh"})
	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("zsh completions error: %v", err)
	}
	buf := make([]byte, 8192)
	n, _ := r.Read(buf)
	output := string(buf[:n])
	if !strings.Contains(output, "#compdef tasia") {
		t.Error("zsh output should contain #compdef tasia")
	}
}

func TestCompletionsFish(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := Run([]string{"completions", "--shell", "fish"})
	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("fish completions error: %v", err)
	}
	buf := make([]byte, 8192)
	n, _ := r.Read(buf)
	output := string(buf[:n])
	if !strings.Contains(output, "complete -c tasia") {
		t.Error("fish output should contain complete -c tasia")
	}
}

func TestCompletionsNoShell(t *testing.T) {
	err := Run([]string{"completions"})
	if err == nil {
		t.Error("completions with no --shell should error")
	}
}

func TestCompletionsUnknown(t *testing.T) {
	err := Run([]string{"completions", "--shell", "powershell"})
	if err == nil {
		t.Error("completions with unknown shell should error")
	}
}
