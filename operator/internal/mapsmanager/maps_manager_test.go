package mapsmanager

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	v1alpha1 "github.com/LorenzoFerro15/bpfima/api/v1alpha1"
	"io"
	"testing"
	"unsafe"
)

func TestPolicyWireLayout(t *testing.T) {
	policy := BpfimaPolicyConfig{MerkleHistoryMaxSize: 1000, MerkleHistoryScope: 1}
	if got := binary.Size(policy); got != 36 {
		t.Fatalf("policy encodes to %d bytes, want kernel ABI size 36", got)
	}
	if unsafe.Offsetof(policy.MerkleHistoryMaxSize) != 24 ||
		unsafe.Offsetof(policy.MerkleHistoryScope) != 28 || unsafe.Offsetof(policy.Reserved) != 32 {
		t.Fatal("policy fields do not match kernel ABI offsets")
	}
}

func defaultPolicyFixture() *v1alpha1.Policy {
	return &v1alpha1.Policy{Spec: v1alpha1.PolicySpec{
		Policy:         v1alpha1.PolicyConfig{Enabled: true, LogLevel: 2, MaxPathDepth: 32},
		Actions:        v1alpha1.ActionConfig{ExtendTPM: true, LogSecurityFS: true, LogKernel: true, TrackContainer: true, BuildDeps: true},
		CgroupPatterns: []v1alpha1.PatternEntry{{Pattern: "/", Enabled: true}, {Pattern: "init.scope", Enabled: true}},
		PathPatterns:   []v1alpha1.PatternEntry{{Pattern: "/proc/", Enabled: true, MatchType: 1}, {Pattern: "/sys/", Enabled: true, MatchType: 1}},
	}}
}

func TestCompletePolicyWireContract(t *testing.T) {
	request, err := BuildPolicyRequest(defaultPolicyFixture(), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	if err := WritePolicyRequest(&buffer, request); err != nil {
		t.Fatal(err)
	}
	if buffer.Len() != 1400 || binary.Size(request.Snapshot) != 1252 {
		t.Fatal("policy ABI size changed")
	}
	// Same independent canonical fixture is asserted by the production C policy test.
	digest := sha256.Sum256(buffer.Bytes()[16:1396])
	if hex.EncodeToString(digest[:]) != "ddba863641f721a846795c580473c17fd1f67ed07f68ef6d33cfdf8a391adf65" {
		t.Fatalf("C/Go canonical policy digest differs: %x", digest)
	}
	if request.Snapshot.Hooks[7].Flags != 7 || request.Snapshot.Hooks[6].Flags != 0 {
		t.Fatal("attribute/default hook IDs differ from the kernel")
	}
}

type shortWriter struct {
	calls   int
	failure error
}

func (writer *shortWriter) Write(value []byte) (int, error) {
	writer.calls++
	if writer.failure != nil {
		return 0, writer.failure
	}
	return len(value) - 1, nil
}

func TestPolicyTransactionErrorsAreNotRetried(t *testing.T) {
	request, err := BuildPolicyRequest(defaultPolicyFixture(), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	writer := &shortWriter{}
	if !errors.Is(WritePolicyRequest(writer, request), io.ErrShortWrite) || writer.calls != 1 {
		t.Fatal("short policy writes must fail without retrying a possibly committed request")
	}
	failure := errors.New("TPM failure")
	writer = &shortWriter{failure: failure}
	if !errors.Is(WritePolicyRequest(writer, request), failure) || writer.calls != 1 {
		t.Fatal("backend failure was hidden/retried")
	}
}

func TestRejectUnsupportedOrPartialPolicy(t *testing.T) {
	policy := defaultPolicyFixture()
	policy.Spec.Actions.ExtendTPM = false
	if _, err := BuildPolicyRequest(policy, "", 0); err == nil {
		t.Fatal("disabled atomic extension accepted")
	}
	policy = defaultPolicyFixture()
	policy.Spec.Hooks.LSMInodeSetattr = &v1alpha1.HookConfig{FilterOverride: 1}
	if _, err := BuildPolicyRequest(policy, "", 0); err == nil {
		t.Fatal("unsupported hook override accepted")
	}
	policy = defaultPolicyFixture()
	policy.Spec.PathPatterns = append(policy.Spec.PathPatterns, v1alpha1.PatternEntry{Pattern: "", Enabled: true})
	if _, err := BuildPolicyRequest(policy, "", 0); err == nil {
		t.Fatal("empty enabled pattern accepted")
	}
}
