// CE-3: ABAC Semantic-Baseline Rules
// These rules express the semantic-baseline deviation logic as Cedar ABAC rules.
// They act as an additive declarative layer alongside the Go runtime scoring logic.

@id("baseline_network_deviation")
forbid(
    principal,
    action == Aegis::Action::"Access",
    resource
) when {
    resource.syscall_class == "network" &&
    resource.deviation_score > 0.8
};

@id("baseline_fs_deviation")
forbid(
    principal,
    action == Aegis::Action::"Access",
    resource
) when {
    resource.syscall_class == "filesystem" &&
    resource.deviation_score > 0.9
};
