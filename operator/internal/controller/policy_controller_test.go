package controller

import "testing"

func TestReadyCheck(t *testing.T) {
	r := &PolicyReconciler{}

	if err := r.ReadyCheck(nil); err == nil {
		t.Fatal("expected not ready before a policy is applied")
	}

	r.applied.Store(true)
	if err := r.ReadyCheck(nil); err != nil {
		t.Fatalf("expected ready after a policy is applied, got %v", err)
	}
}
