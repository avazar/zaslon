package main

import (
	"fmt"
	"io"
	"regexp"
)

var bashCommand = regexp.MustCompile("^[a-zA-Z_][a-zA-Z0-9_.-]*$")

func bashInit(w io.Writer, names []string) error {
	if len(names) == 0 {
		names = []string{"codex", "claude"}
	}
	for _, name := range names {
		if !bashCommand.MatchString(name) {
			return fmt.Errorf("expected an executable name, got %q", name)
		}
	}
	for _, name := range names {
		// Don't replace the user's aliases, functions, builtins, or keywords.
		// The foreground subshell waits for the child even during SIGSTOP.
		if _, err := fmt.Fprintf(w, `if [[ $- == *i* && $(type -t %s) == file ]]; then
    function %s () (
        set +m
        command %s "$@"
        exit "$?"
    )
fi
`, name, name, name); err != nil {
			return err
		}
	}
	return nil
}
