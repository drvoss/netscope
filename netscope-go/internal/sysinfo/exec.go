package sysinfo

import (
	"context"
	"os/exec"
)

func runCommandCtx(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
