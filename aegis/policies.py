"""Server-owned role permissions; unknown roles and actions are denied."""

PERMISSIONS = {
    "support": frozenset({"read_ticket"}),
    "finance": frozenset({"read_financial_report"}),
    "it_admin": frozenset({"read_system_status", "request_account_change"}),
}


def authorize(role: str, action: str) -> bool:
    return action in PERMISSIONS.get(role, frozenset())
