package lockanchor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAcquireSerializesCancelsAndReleasesIdempotently(t *testing.T) {
	release, err := Acquire(nil)
	if err != nil {
		t.Fatalf("acquire stable anchor: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	secondRelease, err := Acquire(ctx)
	if secondRelease != nil {
		_ = secondRelease()
		t.Fatal("canceled acquisition returned a release function")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled acquisition error = %v", err)
	}

	if err := release(); err != nil {
		t.Fatalf("release stable anchor: %v", err)
	}
	if err := release(); err != nil {
		t.Fatalf("repeat stable anchor release: %v", err)
	}

	recovered, err := Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire stable anchor after release: %v", err)
	}
	if err := recovered(); err != nil {
		t.Fatalf("release recovered stable anchor: %v", err)
	}
}

func TestAcquireRejectsCanceledContextBeforeOpeningAnchor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	release, err := Acquire(ctx)
	if release != nil {
		_ = release()
		t.Fatal("pre-canceled acquisition returned a release function")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled acquisition error = %v", err)
	}
}

func TestAcquireContextReentersOnlyWithExplicitActiveLease(t *testing.T) {
	lockedContext, release, err := AcquireContext(context.Background())
	if err != nil {
		t.Fatalf("acquire outer stable anchor: %v", err)
	}

	nestedRelease, err := Acquire(lockedContext)
	if err != nil {
		_ = release()
		t.Fatalf("nested explicit lease did not reenter: %v", err)
	}
	if err := nestedRelease(); err != nil {
		_ = release()
		t.Fatalf("release nested lease: %v", err)
	}
	canceledContext, cancelNested := context.WithCancel(lockedContext)
	cancelNested()
	canceledRelease, err := Acquire(canceledContext)
	if canceledRelease != nil {
		_ = canceledRelease()
		_ = release()
		t.Fatal("canceled nested context returned release function")
	}
	if !errors.Is(err, context.Canceled) {
		_ = release()
		t.Fatalf("canceled nested context error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	foreignRelease, err := Acquire(ctx)
	if foreignRelease != nil {
		_ = foreignRelease()
		_ = release()
		t.Fatal("foreign context bypassed active lease")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		_ = release()
		t.Fatalf("foreign context error = %v", err)
	}

	if err := release(); err != nil {
		t.Fatalf("release outer stable anchor: %v", err)
	}

	recovered, err := Acquire(lockedContext)
	if err != nil {
		t.Fatalf("stale lease context did not reacquire kernel lock: %v", err)
	}
	if err := recovered(); err != nil {
		t.Fatalf("release reacquired stable anchor: %v", err)
	}
}

func TestOuterReleaseWaitsForExplicitNestedLease(t *testing.T) {
	lockedContext, release, err := AcquireContext(context.Background())
	if err != nil {
		t.Fatalf("acquire outer stable anchor: %v", err)
	}
	nestedRelease, err := Acquire(lockedContext)
	if err != nil {
		_ = release()
		t.Fatalf("acquire nested stable anchor: %v", err)
	}

	outerResult := make(chan error, 1)
	go func() {
		outerResult <- release()
	}()
	select {
	case err := <-outerResult:
		_ = nestedRelease()
		t.Fatalf("outer release did not wait for nested lease: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	if err := nestedRelease(); err != nil {
		t.Fatalf("release nested stable anchor: %v", err)
	}
	select {
	case err := <-outerResult:
		if err != nil {
			t.Fatalf("release outer stable anchor: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("outer release remained blocked after nested release")
	}
}

func TestAcquireUsesAccountHomeWhenEnvironmentHomeIsSymlink(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "home")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", link)

	release, err := Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire with symlinked environment home: %v", err)
	}
	if err := release(); err != nil {
		t.Fatalf("release with symlinked environment home: %v", err)
	}
}

func TestValidateMetadata(t *testing.T) {
	valid := metadata{
		anchorUID:        501,
		parentUID:        0,
		effectiveUID:     501,
		anchorMode:       os.ModeDir | 0o750,
		parentMode:       os.ModeDir | 0o755,
		parentWriteKnown: true,
	}
	if err := validateMetadata(valid); err != nil {
		t.Fatalf("valid stable anchor rejected: %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(*metadata)
		message string
	}{
		{
			name: "anchor is not directory",
			mutate: func(value *metadata) {
				value.anchorMode = 0o600
			},
			message: "anchor must be a directory",
		},
		{
			name: "anchor owner differs",
			mutate: func(value *metadata) {
				value.anchorUID = 502
			},
			message: "does not match effective user",
		},
		{
			name: "anchor group writable",
			mutate: func(value *metadata) {
				value.anchorMode = os.ModeDir | 0o770
			},
			message: "anchor permissions",
		},
		{
			name: "parent is not directory",
			mutate: func(value *metadata) {
				value.parentMode = 0o600
			},
			message: "parent must be a directory",
		},
		{
			name: "parent other writable",
			mutate: func(value *metadata) {
				value.parentMode = os.ModeDir | 0o757
			},
			message: "parent permissions",
		},
		{
			name: "parent owned by user",
			mutate: func(value *metadata) {
				value.parentUID = value.effectiveUID
			},
			message: "parent is owned by the effective user",
		},
		{
			name: "parent writability unknown",
			mutate: func(value *metadata) {
				value.parentWriteKnown = false
			},
			message: "parent writability is unknown",
		},
		{
			name: "parent writable through ACL",
			mutate: func(value *metadata) {
				value.parentWritable = true
			},
			message: "parent is writable by the effective user",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := valid
			test.mutate(&value)
			err := validateMetadata(value)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("metadata error = %v, want %q", err, test.message)
			}
		})
	}

	root := valid
	root.anchorUID = 0
	root.parentUID = 0
	root.effectiveUID = 0
	root.parentWritable = true
	if err := validateMetadata(root); err != nil {
		t.Fatalf("root-owned stable anchor rejected: %v", err)
	}
}

func TestRejectKnownLinuxNetworkFilesystems(t *testing.T) {
	for name, filesystemType := range map[string]uint64{
		"nfs":  linuxNFSSuperMagic,
		"cifs": linuxCIFSSuperMagic,
		"smb2": linuxSMB2SuperMagic,
	} {
		t.Run(name, func(t *testing.T) {
			if err := rejectKnownLinuxNetworkFilesystem(
				filesystemType,
			); err == nil {
				t.Fatal("network filesystem unexpectedly accepted")
			}
		})
	}
	if err := rejectKnownLinuxNetworkFilesystem(0xef53); err != nil {
		t.Fatalf("unclassified local filesystem rejected: %v", err)
	}
}
