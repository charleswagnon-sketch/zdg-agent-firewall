from demos.scenarios.approval_cycle import run as approval_cycle
from demos.scenarios.audit_export_verify import run as audit_export_verify
from demos.scenarios.safe_shell_allow import run as safe_shell_allow

SCENARIOS = {
    'safe-shell-allow': safe_shell_allow,
    'approval-cycle': approval_cycle,
    'audit-export-verify': audit_export_verify,
}

