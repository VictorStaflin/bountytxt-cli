package main

import (
	"os"

	"github.com/victorstaflin/bountytxt-cli/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}