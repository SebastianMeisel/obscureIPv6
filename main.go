package main

import (
	"errors"
	"fmt"
	"io"
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

func printUsage(w io.Writer) {
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
	cmd.Stdin = os.Stdin
	cmd.Stderr = errOut

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	streamErr := streamOutput(stdout, out, state)
	waitErr := cmd.Wait()

	if streamErr != nil {
		return streamErr
	}
	if waitErr != nil {
		return waitErr
	}
	return nil
}

func streamOutput(r io.Reader, w io.Writer, state State) error {
	if !ObscuringEnabled() {
		_, err := io.Copy(w, r)
		return err
	}
	return StreamObscure(r, w, state)
}

func filterStdin(out io.Writer, state State) error {
	return streamOutput(os.Stdin, out, state)
}

func exitCodeFromErr(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return 1
}
