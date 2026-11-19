# Keep a foreground shell waiting while Zaslon pauses the interactive program.
codex() (
    set +m
    command codex "$@"
    exit "$?"
)
