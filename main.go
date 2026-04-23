package main

import (
	"fmt"
	"os"

	"github.com/emilmelnikov/xray-easy/internal/app"
	_ "github.com/xtls/xray-core/main/distro/all"
)

func main() {
	if err := app.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
