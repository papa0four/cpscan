// cmd/cpscan/main.go
package main

import (
    "os"
    "fmt"

    "github.com/papa0four/cpscan/cmd/commands"
    _ "github.com/papa0four/cpscan/cmd/commands/security"
) 

func main() {
    if err := cmd.RootCmd.Execute(); err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}
