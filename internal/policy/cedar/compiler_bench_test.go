package cedar

import "testing"

func BenchmarkCompileToBPF(b *testing.B) {
	policy := `@id("p1")
forbid(principal, action, resource) when { resource.binary_hash == "abcdef0123456789" };
@id("p2")
forbid(principal, action, resource) when { resource.path_pattern like "/workspace/.git/*" };`
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = CompileToBPF(policy)
	}
}
