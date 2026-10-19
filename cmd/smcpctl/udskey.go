package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
)

// udsCmd is "smcpctl uds key --out <file>": it generates a UDS Harness
// Profile bearer key from 256 bits of CSPRNG output (SR-2.3-1), writes the
// key to a new file with mode 0600 for the harness user, and prints the
// [[uds.peer]] key_hash line. Only the Argon2id verifier goes into the
// configuration; the Gateway never stores the key.
func udsCmd(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "key" {
		return errors.New("usage: smcpctl uds key --out <file>")
	}
	fs := flag.NewFlagSet("uds key", flag.ContinueOnError)
	path := fs.String("out", "", "write the new bearer key to this file (created with mode 0600; must not exist)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *path == "" || fs.NArg() > 0 {
		return errors.New("usage: smcpctl uds key --out <file>")
	}
	key := ids.Secret() // 32 bytes from crypto/rand
	h, err := keys.HashPassword(key)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, key); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(out, "key_hash = %q\n", h)
	return nil
}
