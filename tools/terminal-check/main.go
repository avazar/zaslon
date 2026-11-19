package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"

	"github.com/avazar/zaslon/internal/procs"
)

func main() {
	parent, err := strconv.Atoi(os.Args[1])
	if err != nil {
		panic(err)
	}
	root, err := strconv.Atoi(os.Args[2])
	if err != nil {
		panic(err)
	}
	name := os.Args[3]
	if name != "codex" && name != "cat" {
		panic("unknown fixture")
	}
	backend := procs.New()
	all, err := backend.List()
	if err != nil {
		panic(err)
	}
	var session []procs.Proc
	validRoot := false
	for _, p := range all {
		group, groupErr := syscall.Getpgid(p.PID)
		if groupErr != nil || group != root {
			continue
		}
		session = append(session, p)
		if p.PID == root && p.PPID == parent && p.Name == name {
			validRoot = true
		}
	}
	if !validRoot {
		panic("wrong foreground process")
	}
	rule := procs.Rule{Names: []string{name}}
	if name == "codex" {
		preset, _ := procs.PresetByID("codex")
		rule = preset.Rule()
	}
	targets := procs.Filter(session, []procs.Target{{ID: name, Name: name, Rule: rule}}, os.Getpid())
	if len(targets) == 0 {
		panic("no targets")
	}
	for _, p := range targets {
		if err := backend.Freeze(p); err != nil {
			panic(err)
		}
		fmt.Fprintf(os.Stderr, "froze %s pid=%d\n", p.Name, p.PID)
	}
	fmt.Println("paused")
	var action string
	if _, err := fmt.Scanln(&action); err != nil || action != "resume" {
		panic("missing resume")
	}
	for _, p := range targets {
		if err := backend.Resume(p); err != nil {
			panic(err)
		}
		fmt.Fprintf(os.Stderr, "resumed %s pid=%d\n", p.Name, p.PID)
	}
	fmt.Println("resumed")
}
