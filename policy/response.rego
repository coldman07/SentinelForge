package sentinelforge.response

import rego.v1

low_impact_actions := {"tag_host", "collect_artifacts"}
high_impact_actions := {"network_isolate_host", "kill_process", "disable_account"}

default allow := false
default requires_approval := false
default reason := "action is not permitted by policy"

justified if {
	count(trim_space(input.justification)) >= 12
}

valid_approval if {
	input.approval.approver_role in {"approver", "admin"}
	input.approval.approver_id != input.actor.id
}

allow if {
	input.action in low_impact_actions
	input.actor.role in {"analyst", "approver", "admin"}
	justified
}

allow if {
	input.action in high_impact_actions
	input.actor.role in {"analyst", "approver", "admin"}
	justified
	valid_approval
}

requires_approval if {
	input.action in high_impact_actions
	not valid_approval
}

reason := "approval is required from a different approver" if {
	requires_approval
}

reason := "policy approved; no response action was executed" if {
	allow
}

decision := {
	"allow": allow,
	"requires_approval": requires_approval,
	"reason": reason,
}
