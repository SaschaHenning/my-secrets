package sync

import (
	"bufio"
	"strings"
)

func bufioReader(s string) *bufio.Reader {
	return bufio.NewReader(strings.NewReader(s))
}
