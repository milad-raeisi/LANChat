// Command lanchat is a secure, terminal-based instant messenger for local
// networks. See `lanchat --help`.
package main

import (
	"os"

	"github.com/milad-raeisi/LANChat/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
