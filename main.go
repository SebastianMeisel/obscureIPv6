package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// main is the CLI entry point.
//
// Supported subcommands:
//
//	obscureipv6 info
//	obscureipv6 filter
//	obscureipv6 ip [args...]
//	obscureipv6 tracepath [args...]
func main() {
	state := DetectState()

	// Export the detected values for child processes, similar to the original
	// Bash snippet's environment exports.
	if state.Dev != "" {
		_ = os.Setenv("myIPv6Dev", state.Dev)
	}
	if state.Prefix != "" {
		_ = os.Setenv("myIPv6Prefix", state.Prefix)
	}

	if len(os.Args) < 2 {
		printUsage(os.Stderr)
		os.Exit(2)
	}

	switch os.Args[1] {
	case "info":
		fmt.Printf("myIPv6Dev=%s\n", state.Dev)
		fmt.Printf("myIPv6Prefix=%s\n", state.Prefix)
		if state.HasPrefix() {
			fmt.Printf("obscuredPrefix=%s\n", ObscuredPrefixString(state.PrefixParts))
		} else {
			fmt.Printf("obscuredPrefix=\n")
		}

	case "filter":
		if err := filterStdin(os.Stdout, state); err != nil {
			fmt.Fprintf(os.Stderr, "filter: %v\n", err)
			os.Exit(1)
		}

	case "ip":
		args := append([]string{"-h", "-s", "--color=always"}, os.Args[2:]...)
		if err := runAndFilter("/usr/sbin/ip", args, os.Stdout, os.Stderr, state); err != nil {
			fmt.Fprintf(os.Stderr, "ip: %v\n", err)
			os.Exit(exitCodeFromErr(err))
		}

	case "tracepath":
		if err := runAndFilter("/usr/sbin/tracepath", os.Args[2:], os.Stdout, os.Stderr, state); err != nil {
			fmt.Fprintf(os.Stderr, "tracepath: %v\n", err)
			os.Exit(exitCodeFromErr(err))
		}

	default:
		printUsage(os.Stderr)
		os.Exit(2)
	}
}

// printUsage writes a short usage text.
func printUsage(w *os.File) {
	fmt.Fprintln(w, `Usage:
  obscureipv6 info
  obscureipv6 filter
  obscureipv6 ip [ip-args...]
  obscureipv6 tracepath [tracepath-args...]

Environment:
  dontObscureIPv6=1   Disable obscuring`)
}

// runAndFilter executes a command, captures its stdout, rewrites it if enabled,
// writes the result to out, and passes stderr through unchanged.
func runAndFilter(path string, args []string, out, errOut *os.File, state State) error {
	cmd := exec.Command(path, args...)
	cmd.Env = os.Environ()

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = errOut

	err := cmd.Run()

	text := stdout.String()
	if ObscuringEnabled() {
		text = ObscureIPv6Text(text, state)
	}

	if _, writeErr := out.WriteString(text); writeErr != nil {
		return writeErr
	}

	if err != nil {
		return err
	}
	return nil
}

// filterStdin reads stdin, obscures matching IPv6 addresses if enabled, and
// writes the result to out.
func filterStdin(out *os.File, state State) error {
	var buf bytes.Buffer
	reader := bufio.NewReader(os.Stdin)

	if _, err := buf.ReadFrom(reader); err != nil {
		return err
	}

	text := buf.String()
	if ObscuringEnabled() {
		text = ObscureIPv6Text(text, state)
	}

	_, err := out.WriteString(text)
	return err
}

// exitCodeFromErr preserves the wrapped command's exit status if possible.
func exitCodeFromErr(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return 1
}
