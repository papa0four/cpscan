// cmd/commands/version.go
package cmd

/*
Version is the current application version.
It defaults to the active development stage and is overridden
at build time via -ldflags "-X github.com/papa0four/cpscan/cmd/commands.Version=..."
*/
var Version = "v0.1.0-alpha"