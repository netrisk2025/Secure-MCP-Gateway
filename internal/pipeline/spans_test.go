package pipeline

import (
	"context"
	"runtime"
	"testing"
	"time"
)

func burn(d time.Duration) {
	for t0 := time.Now(); time.Since(t0) < d; {
	}
}

// TestSpanTimerMeasuresStagesAndCPU: stage spans carry monotonic times,
// thread CPU time and the policy objects set after the decision; filter
// runs become filter spans whose CPU is added to their stage.
func TestSpanTimerMeasuresStagesAndCPU(t *testing.T) {
	cpuClock := runtime.GOOS == "linux" || runtime.GOOS == "darwin"
	st := NewSpanTimer("corr-1")
	end := st.Start(SpanDecision)
	// Burn CPU time, not wall-clock time, past the 1ms CPU floor checked
	// below: on a loaded host the thread is not on a CPU for the whole
	// wall-clock interval.
	burnCPU(10 * time.Millisecond)
	end()
	st.PolicyRevision, st.Rule = "r1", "r1/ro/a"
	end = st.Start(SpanRequestInspection)
	time.Sleep(2 * time.Millisecond)
	end()
	st.AddFilterRuns([]FilterRun{{Stage: StageRequest, Filter: "f", Start: time.Now(), Duration: time.Millisecond, CPU: 4 * time.Millisecond}})
	spans := st.Finish()
	if len(spans) != 3 {
		t.Fatalf("%d spans", len(spans))
	}
	d, insp, f := spans[0], spans[1], spans[2]
	if d.Stage != SpanDecision || d.PolicyRevision != "" || d.CorrelationID != "corr-1" || d.Duration() < 3*time.Millisecond {
		t.Fatalf("decision span %+v", d)
	}
	if cpuClock && (d.CPU < time.Millisecond || !d.CPUMeasured) {
		t.Fatalf("decision span CPU %v measured %v", d.CPU, d.CPUMeasured)
	}
	if insp.PolicyRevision != "r1" || insp.Rule != "r1/ro/a" || f.Filter != "f" || f.Stage != SpanFilter || f.PolicyRevision != "r1" {
		t.Fatalf("spans %+v %+v", insp, f)
	}
	if insp.CPU < 4*time.Millisecond {
		t.Fatalf("inspection CPU %v lacks the filter's 4ms", insp.CPU)
	}
	cpu, ok := MeasureCPU(func() { burnCPU(10 * time.Millisecond) })
	if ok != cpuClock || (ok && cpu < time.Millisecond) {
		t.Fatalf("MeasureCPU %v %v", cpu, ok)
	}
}

// TestSpanTimerWaitsAreNotMeasured: a stage's waits (Wait) and a filter's
// waits (WaitUnmeasured) run with the goroutine unlocked from its thread
// and are not counted in the CPU time, while the work around them is; a
// nil timer runs the wait, and Finish closes a stage left open.
func TestSpanTimerWaitsAreNotMeasured(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("no per-thread CPU clock")
	}
	st := NewSpanTimer("corr-2")
	end := st.Start(SpanDispatch)
	burnCPU(3 * time.Millisecond)
	ran := false
	st.Wait(func() { burnCPU(30 * time.Millisecond); ran = true })
	end()
	if !ran {
		t.Fatal("wait did not run")
	}
	spans := st.Finish()
	if len(spans) != 1 || !spans[0].CPUMeasured {
		t.Fatalf("spans %+v", spans)
	}
	if c := spans[0].CPU; c < 3*time.Millisecond || c >= 20*time.Millisecond {
		t.Fatalf("dispatch CPU %v: want the 3ms around the wait, not the 30ms inside it", c)
	}
	if d := spans[0].Duration(); d < 30*time.Millisecond {
		t.Fatalf("dispatch duration %v does not include the wait", d)
	}

	var nilTimer *SpanTimer
	ran = false
	nilTimer.Wait(func() { ran = true })
	if !ran {
		t.Fatal("nil timer did not run the wait")
	}

	st = NewSpanTimer("corr-3")
	st.Start(SpanDecision) // never ended
	burn(2 * time.Millisecond)
	if spans := st.Finish(); len(spans) != 0 || st.cur != nil {
		t.Fatalf("open stage after Finish: %+v", spans)
	}

	cpu, ok := measureCPU(context.Background(), func(ctx context.Context) {
		burnCPU(3 * time.Millisecond)
		WaitUnmeasured(ctx, func() { burnCPU(30 * time.Millisecond) })
	})
	if !ok || cpu < 3*time.Millisecond || cpu >= 20*time.Millisecond {
		t.Fatalf("filter CPU %v %v: want the 3ms outside the wait", cpu, ok)
	}
	ran = false
	WaitUnmeasured(context.Background(), func() { ran = true })
	if !ran {
		t.Fatal("WaitUnmeasured outside a measured run did not run fn")
	}
}

// burnCPU spins until its thread has used d of CPU time (d of wall-clock
// time where there is no per-thread clock).
func burnCPU(d time.Duration) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	c0, ok := threadCPU()
	if !ok {
		burn(d)
		return
	}
	for {
		if c, _ := threadCPU(); c-c0 >= d {
			return
		}
	}
}
