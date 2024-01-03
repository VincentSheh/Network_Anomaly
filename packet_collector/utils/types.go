package utils

import (
	"time"
)

type BWInfo struct {
	Bw        string // black or white list
	LastCheck time.Time
}
