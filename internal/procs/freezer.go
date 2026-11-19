package procs

// FreezerGroup identifies a private Linux cgroup across guard restarts.
// Old journal entries without a group use the original signal backend.
type FreezerGroup struct {
	Path  string `json:"path"`
	Inode uint64 `json:"inode"`
}

type GroupController interface {
	FreezeTracked(Proc, func(*FreezerGroup) error) (*FreezerGroup, error)
	CheckGroup(Proc, *FreezerGroup) error
	ReleaseGroup(Proc, *FreezerGroup) error
	ForgetGroup(Proc, *FreezerGroup) error
}
