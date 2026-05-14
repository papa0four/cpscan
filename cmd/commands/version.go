// cmd/commands/version.go
package cmd

/*
Version is the current application version.
It defaults to the active development stage and is overridden
at build time via -ldflags "-X github.com/papa0four/orkowatch/cmd/commands.Version=..."
*/
var Version = "dev"
