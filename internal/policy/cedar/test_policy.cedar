@id("policy_entry_1")
forbid(
    principal == Aegis::Repo::"123",
    action == Aegis::Action::"Access",
    resource
) when { resource.binary_hash == "badhash" };

@id("policy_entry_2")
permit(
    principal == Aegis::Repo::"123",
    action == Aegis::Action::"Access",
    resource
);
