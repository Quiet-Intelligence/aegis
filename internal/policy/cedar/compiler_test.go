package cedar

import (
	"testing"
	"reflect"
)

func TestCompileToBPF(t *testing.T) {
	policy := `
@id("policy_entry_1")
forbid(
    principal == Aegis::Repo::"1",
    action == Aegis::Action::"Access",
    resource
) when { resource.binary_hash == "abc123hash" };

@id("policy_entry_2")
forbid(
    principal == Aegis::Repo::"1",
    action == Aegis::Action::"Access",
    resource
) when { resource.path_pattern like "/etc/shadow*" };
`

	expected := BPFMapFormat{
		DeniedHashes: []string{"abc123hash"},
		DeniedPaths:  []string{"/etc/shadow"},
	}

	actual := CompileToBPF(policy)

	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("CompileToBPF output mismatch. Expected %v, got %v", expected, actual)
	}
}
