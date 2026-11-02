// Command security-watch is a server monitoring service.
//
// It watches and reports what it notices, changing nothing in the system:
//   - web server log: path scanning, access guessing, request floods,
//     injection attempts;
//   - auth log: SSH password guessing, successful logins, sudo usage;
//   - files: replacement, creation, deletion, permission changes;
//   - listening ports and running programs: appearance of undeclared ones;
//   - database: changes to fields the application must not change.
//
// Blocking an address is a separate command; self-directed blocking is off by
// default and is enabled with conditions.
//
// This file only parses the command line; the work lives in internal/watch.
//
// Usage: security-watch -config /etc/security-watch/config.json
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/Insider515/security-watch-daemon/internal/watch"
)

// version is set at build time: go build -ldflags="-X main.version=1.0.0".
// "dev" means the build carries no version.
var version = "dev"

func main() {
	flags := parseFlags()

	if flags.showVersion {
		fmt.Printf("security-watch %s %s/%s %s\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return
	}

	// Two commands work without a configuration file: they are run on your own
	// machine over files you received.
	if flags.tunePath != "" {
		exitOnError(watch.Tune(flags.tunePath))
		return
	}
	if flags.verifyPath != "" {
		exitOnError(watch.VerifyFile(flags.verifyPath))
		return
	}

	cfg, err := watch.LoadConfig(flags.configPath)
	exitOnError(err)
	watch.SetupLogging(cfg.Log, os.Stderr)
	if flags.check {
		exitOnError(watch.CheckConfig(cfg))
		return
	}
	if flags.showStats {
		exitOnError(watch.PrintMetrics(cfg.StateDir))
		return
	}
	exitOnError(os.MkdirAll(cfg.StateDir, 0o750))

	// Control commands run and exit: watching is not started, so that two copies
	// of the service do not read the same logs.
	if flags.control.Requested() {
		exitOnError(watch.RunControlCommand(cfg, flags.control))
		return
	}

	service, err := watch.NewService(cfg, flags.configPath)
	exitOnError(err)
	defer service.Close()

	if flags.once {
		service.ScanOnce()
		return
	}

	// Cancellation by signal: the context shuts down every watcher at once.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	finished := make(chan struct{})
	go func() {
		service.Run(ctx)
		close(finished)
	}()

	<-ctx.Done()
	// The shutdown is reported before waiting for the watchers: if it is not the
	// operator who is stopping the service, this is the event of the day.
	service.Stopped("received a stop signal")
	<-finished
	slog.Info("watching stopped")
}

// cliFlags holds the command-line arguments.
type cliFlags struct {
	configPath  string
	once        bool
	check       bool
	showStats   bool
	showVersion bool
	verifyPath  string
	tunePath    string
	control     watch.ControlRequest
}

// parseFlags parses the command line.
func parseFlags() cliFlags {
	flags := cliFlags{}
	flag.StringVar(&flags.configPath, "config", "/etc/security-watch/config.json", "path to the configuration file")
	flag.BoolVar(&flags.once, "once", false, "one pass over files, ports, processes and the database, without continuous watching")
	flag.BoolVar(&flags.check, "check", false, "check the configuration and exit")
	flag.BoolVar(&flags.showStats, "stats", false, "print the service's own counters and exit")
	flag.BoolVar(&flags.showVersion, "version", false, "print the version and exit")
	flag.StringVar(&flags.verifyPath, "verify", "", "verify the chain in an event file and exit")
	flag.StringVar(&flags.tunePath, "tune", "", "derive thresholds from a web server log and exit")
	// The decision to block is made by a human: the service never shuts anyone
	// out on its own, it only collects proposals with evidence.
	flag.BoolVar(&flags.control.Candidates, "candidates", false, "print block proposals and exit")
	flag.BoolVar(&flags.control.Actors, "actors", false, "print actors ranked by score and exit")
	flag.StringVar(&flags.control.Dossier, "dossier", "", "print the dossier for an address (or * for the list) and exit")
	flag.StringVar(&flags.control.Block, "block", "", "block an address (your decision) and exit")
	flag.StringVar(&flags.control.Unblock, "unblock", "", "unblock an address and exit")
	flag.StringVar(&flags.control.Action, "action", "", "run the named action (see actions in the configuration)")
	flag.StringVar(&flags.control.ActionArg, "arg", "", "value for the action: user id, address, key")
	flag.Parse()
	return flags
}

// exitOnError stops the program with a clear message if an error occurred.
func exitOnError(err error) {
	if err != nil {
		slog.Error("stopping because of an error", slog.Any("error", err))
		os.Exit(1)
	}
}
