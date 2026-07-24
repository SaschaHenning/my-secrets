package policy

import (
	"context"
	"fmt"

	"github.com/SaschaHenning/my-secrets/internal/lockanchor"
)

func acquireSharedPolicyLock(
	ctx context.Context,
	mount string,
) (func() error, error) {
	release, err := lockanchor.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"acquire shared policy setup lock for mount %q: %w",
			mount,
			err,
		)
	}
	return release, nil
}
