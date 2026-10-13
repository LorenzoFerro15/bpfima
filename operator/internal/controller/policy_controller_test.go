package controller

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/LorenzoFerro15/bpfima/api/v1alpha1"
	"github.com/LorenzoFerro15/bpfima/internal/mapsmanager"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func testReconciler(t *testing.T, endpoint string) *PolicyReconciler {
	t.Helper()
	t.Setenv("NODE_NAME", "node-test")
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	// An existing node with no labels still needs its generic/root policy applied.
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-test"}}
	return &PolicyReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(node).Build(),
		Scheme: scheme, Log: logr.Discard(), PolicyEndpoint: endpoint,
		StatisticsPath: filepath.Join(t.TempDir(), "statistics.csv")}
}

func TestReconcileUnlabeledNodeAppliesCompletePolicy(t *testing.T) {
	endpoint := filepath.Join(t.TempDir(), "policy_apply")
	if err := os.WriteFile(endpoint, nil, 0600); err != nil {
		t.Fatal(err)
	}
	reconciler := testReconciler(t, endpoint)
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{}); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() != 1400 {
		t.Fatalf("incomplete policy transaction: %v", err)
	}
	var request mapsmanager.PolicyRequest
	if err := binary.Read(file, binary.LittleEndian, &request); err != nil {
		t.Fatal(err)
	}
	if request.Version != 2 || request.NamespaceID[0] != 0 || request.Snapshot.Config.Enabled != 1 ||
		request.Snapshot.Cgroups[0].Pattern[0] != '/' || request.Snapshot.Hooks[7].Flags != 7 {
		t.Fatal("root transaction omitted configuration, patterns or attribute hook")
	}
}

func TestReconcilePropagatesPolicyBackendFailure(t *testing.T) {
	endpoint := filepath.Join(t.TempDir(), "missing-policy-endpoint")
	reconciler := testReconciler(t, endpoint)
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{}); err == nil {
		t.Fatal("policy backend failure was reported as successful activation")
	}
	if _, err := os.Stat(endpoint); !os.IsNotExist(err) {
		t.Fatal("controller created a substitute policy endpoint")
	}
}
