//go:build !darwin && !linux

package lockanchor

func registerHolder(_ bool) func() { return func() {} }

func holders() []int { return nil }
