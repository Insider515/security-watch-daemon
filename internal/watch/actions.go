// Response actions at the application level: revoke sessions, close an account,
// rotate a key. Executed only on a human command.
package watch

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// ActionsConfig - named response commands that can be run with the -action
// flag. The service never calls them on its own.
type ActionsConfig struct {
	Enabled bool `json:"enabled"`
	// Action name -> command. %s is replaced with the given value.
	Commands map[string]string `json:"commands"`
}

// RunAction executes the named action.
func RunAction(cfg ActionsConfig, name, argument string, emit func(Event)) error {
	if !cfg.Enabled {
		return fmt.Errorf("actions are disabled in the configuration (actions.enabled)")
	}
	command, known := cfg.Commands[name]
	if !known {
		return fmt.Errorf("action %q is not defined; available: %s", name, strings.Join(actionNames(cfg), ", "))
	}
	if err := validateArgument(argument); err != nil {
		return err
	}
	output, err := runCommand(command, argument)
	if err != nil {
		return fmt.Errorf("action %q failed: %w (%s)", name, err, output)
	}
	emit(Event{
		At: time.Now(), Source: "action", Kind: "action_done", Severity: SevInfo,
		Subject: name + " " + argument, Count: 1,
		Details: map[string]string{"by": "operator decision", "output": sampleOf(output, 300)},
	})
	fmt.Printf("action %q executed for %q\n%s\n", name, argument, output)
	return nil
}

// actionNames lists the defined actions for the hint message.
func actionNames(cfg ActionsConfig) []string {
	names := make([]string, 0, len(cfg.Commands))
	for name := range cfg.Commands {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// validateArgument checks the value substituted into the command: letters,
// digits, dot, dash, underscore, at sign and colon are allowed.
func validateArgument(value string) error {
	if value == "" {
		return fmt.Errorf("empty value")
	}
	if len(value) > 120 {
		return fmt.Errorf("value is too long")
	}
	for _, symbol := range value {
		isLetter := (symbol >= 'a' && symbol <= 'z') || (symbol >= 'A' && symbol <= 'Z')
		isDigit := symbol >= '0' && symbol <= '9'
		if !isLetter && !isDigit && symbol != '.' && symbol != '_' && symbol != '-' && symbol != '@' && symbol != ':' {
			return fmt.Errorf("disallowed character in value %q", value)
		}
	}
	return nil
}
