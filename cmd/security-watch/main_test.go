package main

import (
	"flag"
	"os"
	"testing"
)

// Command-line parsing collects the control commands into a single
// ControlRequest, which is what the engine receives.
func TestParseFlagsControl(t *testing.T) {
	savedArgs, savedFlags := os.Args, flag.CommandLine
	defer func() { os.Args, flag.CommandLine = savedArgs, savedFlags }()

	flag.CommandLine = flag.NewFlagSet("security-watch", flag.ContinueOnError)
	os.Args = []string{"security-watch", "-config", "/tmp/c.json", "-block", "203.0.113.9", "-arg", "2648"}

	flags := parseFlags()
	if flags.configPath != "/tmp/c.json" {
		t.Errorf("configuration path: %q", flags.configPath)
	}
	if flags.control.Block != "203.0.113.9" || flags.control.ActionArg != "2648" {
		t.Errorf("control request: %+v", flags.control)
	}
	if !flags.control.Requested() {
		t.Error("the control request must count as requested")
	}
}

// Without control commands the service must go on watching instead of running a
// command and exiting.
func TestParseFlagsWatchMode(t *testing.T) {
	savedArgs, savedFlags := os.Args, flag.CommandLine
	defer func() { os.Args, flag.CommandLine = savedArgs, savedFlags }()

	flag.CommandLine = flag.NewFlagSet("security-watch", flag.ContinueOnError)
	os.Args = []string{"security-watch", "-once"}

	flags := parseFlags()
	if !flags.once {
		t.Error("the -once flag was not parsed")
	}
	if flags.control.Requested() {
		t.Errorf("no control command was requested: %+v", flags.control)
	}
	if flags.configPath != "/etc/security-watch/config.json" {
		t.Errorf("default configuration path: %q", flags.configPath)
	}
}

// The version flag: without it there is no way to tell which build is running on
// a server. The version is set at build time, and "dev" means it was not.
func TestParseFlagsVersion(t *testing.T) {
	savedArgs, savedFlags := os.Args, flag.CommandLine
	defer func() { os.Args, flag.CommandLine = savedArgs, savedFlags }()

	flag.CommandLine = flag.NewFlagSet("security-watch", flag.ContinueOnError)
	os.Args = []string{"security-watch", "-version"}

	flags := parseFlags()
	if !flags.showVersion {
		t.Error("the -version flag was not parsed")
	}
	if version == "" {
		t.Error("the version must not be empty even without build flags")
	}
}
