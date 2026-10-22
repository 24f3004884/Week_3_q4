import re
import secrets


def extract_evidence(transcript):

    evidence = re.findall(
        r"\[(.*?)\]",
        transcript
    )

    return evidence[:4]


def choose_root_cause(incident):

    causes = incident.allowedRootCauses

    if causes:
        return causes[0]

    return "unknown"


def choose_diagnostics(tool_catalog):

    diagnostics = []

    for tool in tool_catalog:

        if len(diagnostics) >= 3:
            break

        diagnostics.append(tool)

    return diagnostics


def build_plan(request):

    evidence = extract_evidence(
        request.incident.transcript
    )

    root_cause = choose_root_cause(
        request.incident
    )

    diagnostics = choose_diagnostics(
        request.toolCatalog
    )

    return {
        "rootCause": root_cause,
        "evidence": evidence,
        "diagnostics": diagnostics
    }