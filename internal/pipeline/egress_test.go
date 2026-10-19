package pipeline

import (
	"context"
	"testing"
)

func TestNoEgressDefault(t *testing.T) {
	att, err := NoEgress{}.Attach(context.Background(), EgressRequest{Alias: "x"})
	if err != nil || att.Enforced || len(att.Env) != 0 {
		t.Fatalf("%+v %v", att, err)
	}
	if err := att.Close(); err != nil {
		t.Fatal(err)
	}
	var _ EgressAttacher = NoEgress{}
}
