import secrets


def new_action_id():
    return secrets.token_hex(8)


def build_dispatch(
        tool_name,
        evidence,
        service):

    action_id = new_action_id()

    return {
        "actionId": action_id,
        "callId": action_id,
        "phase": "diagnostic",
        "toolName": tool_name,
        "arguments": {
            "service": service
        },
        "attempt": 1,
        "evidence": evidence[:1]
    }