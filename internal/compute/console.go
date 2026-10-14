package compute

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
)

// consoleResend is how often unchanged console output is sent again, so a
// new control-plane leader (which keeps it in memory) gets it.
const consoleResend = 5 * time.Minute

type consoleSent struct {
	size int64
	mod  time.Time
	at   time.Time
}

// sendConsole sends the tail of a VM's serial console to the control
// plane when it has changed.
func (h *Host) sendConsole(ctx context.Context, vm *VM) {
	path := filepath.Join(vm.Dir, "console.log")
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	h.mu.Lock()
	last := h.consoles[vm.Instance.ID]
	h.mu.Unlock()
	if fi.Size() == last.size && fi.ModTime().Equal(last.mod) && time.Since(last.at) < consoleResend {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	if off := fi.Size() - ec2meta.MaxConsole; off > 0 {
		f.Seek(off, io.SeekStart)
	}
	out, err := io.ReadAll(io.LimitReader(f, ec2meta.MaxConsole))
	if err != nil {
		return
	}
	if err := h.Control.SendConsole(ctx, ec2meta.ConsoleOutput{InstanceID: vm.Instance.ID, Output: out}); err != nil {
		if ctx.Err() == nil {
			h.logf("compute: sending console of %s: %v", vm.Instance.ID, err)
		}
		return
	}
	h.mu.Lock()
	if h.consoles == nil {
		h.consoles = map[string]consoleSent{}
	}
	h.consoles[vm.Instance.ID] = consoleSent{size: fi.Size(), mod: fi.ModTime(), at: time.Now()}
	h.mu.Unlock()
}
