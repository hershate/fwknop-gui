package main

import "embed"

// webContent holds the embedded UI assets under web/.
//
//go:embed web
var webContent embed.FS
