import secrets


def hex_trace():
    return secrets.token_hex(16)


def hex_span():
    return secrets.token_hex(8)


def build_trace(
        run_id,
        marker):

    trace_id = hex_trace()

    server_span = {
        "traceId": trace_id,
        "spanId": hex_span(),
        "name": "POST /v2/incidents",
        "kind": 2
    }

    agent_span = {
        "traceId": trace_id,
        "spanId": hex_span(),
        "name": "invoke_agent",
        "kind": 1
    }

    model_span = {
        "traceId": trace_id,
        "spanId": hex_span(),
        "name": "incident-plan",
        "kind": 3
    }

    return {
        "resourceSpans":[
            {
                "scopeSpans":[
                    {
                        "spans":[
                            server_span,
                            agent_span,
                            model_span
                        ]
                    }
                ]
            }
        ]
    }