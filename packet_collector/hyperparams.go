package main

import (
	"math/rand"
	"time"
)

type Hyperparams struct {
	CheckInterval       time.Duration // Separate BL, WL, Unassigned Time Elapsed Interval
	WLDurationThreshold time.Duration
	WLRecheckInterval   time.Duration
	Seed                *rand.Rand
}

var Config = Hyperparams{
	CheckInterval:       1000 * time.Millisecond, // Interval set to 1000 milliseconds (1 second)
	WLDurationThreshold: 5000 * time.Millisecond,
	WLRecheckInterval:   20000 * time.Millisecond,
	Seed:                rand.New(rand.NewSource(9022)),
}
