//go:build unix

package testport

import (
	"bufio"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// A port handed out in one process is reserved against another process
// running at the same time (go test runs packages as parallel processes):
// a child process reserves ports and reports them, and while it runs this
// process cannot reserve any of them.
func TestReservedAcrossProcesses(t *testing.T) {
	if os.Getenv("SMCP_TESTPORT_CHILD") == "1" {
		for range 20 {
			p, err := Port()
			if err != nil {
				os.Exit(2)
			}
			os.Stdout.WriteString(strconv.Itoa(p) + "\n")
		}
		os.Stdout.WriteString("done\n")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n') // hold the locks until told to exit
		os.Exit(0)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestReservedAcrossProcesses$")
	cmd.Env = append(os.Environ(), "SMCP_TESTPORT_CHILD=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { stdin.Close(); _ = cmd.Wait() }()
	var ports []int
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "done" {
			break
		}
		if p, err := strconv.Atoi(line); err == nil {
			ports = append(ports, p)
		}
	}
	if len(ports) != 20 {
		t.Fatalf("child reported %d ports", len(ports))
	}
	for _, p := range ports {
		if reserve(p) {
			t.Fatalf("port %d reserved by the child was reserved again here", p)
		}
	}
}
