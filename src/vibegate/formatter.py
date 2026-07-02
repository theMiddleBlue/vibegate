"""Render classified findings into an ANSI terminal report + host context.

Produces an ``AnalysisResult`` consumed by host adapters. ``should_block`` is set
when any finding lands in a critical category (EXEC_INPUT / DB_QUERY).
"""

from __future__ import annotations

from .colors import BOLD, CYAN, GRAY, GREEN, ORANGE, RED, RESET, YELLOW
from .guidance import get_guidance
from .models import AnalysisResult, ClassifiedFinding

SEVERITY_COLOR = {
    "CRITICAL": RED,
    "HIGH": ORANGE,
    "MEDIUM": YELLOW,
    "LOW": GREEN,
}

CONFIDENCE_LABEL = {
    "high": "✓ HIGH",
    "medium": "~ MEDIUM",
    "low": "? LOW",
}

BLOCKING_CATEGORIES = (
    "EXEC_INPUT",
    "DB_QUERY",
    "TEMPLATE_INJECTION",
    "INSECURE_DESERIALIZATION",
    "NOSQL_QUERY",
    "PATH_TRAVERSAL",
    "XXE",
    "XSS_SINK",
    "FILE_UPLOAD",
)


def format_output(
    classified: list[ClassifiedFinding], file_path: str, language: str
) -> AnalysisResult:
    lines: list[str] = []
    context_parts: list[str] = []
    block_reason = ""

    lines.append(f"\n{BOLD}{CYAN}╔══════ VibeGate · pre-write security ══════╗{RESET}")
    lines.append(f"{GRAY}  File: {file_path} ({language}){RESET}")
    lines.append(f"{BOLD}{CYAN}╚{'═' * 38}╝{RESET}\n")

    for finding in classified:
        tech = finding.technical_category
        sem = finding.semantic_type
        line = finding.line
        snip = finding.snippet
        conf = finding.confidence
        g = get_guidance(tech, sem)

        sev_color = SEVERITY_COLOR[g["severity"]]
        conf_label = CONFIDENCE_LABEL[conf]

        lines.append(
            f"{sev_color}{BOLD}  {g['severity_emoji']} [{g['severity']}] Line {line}{RESET}"
        )
        lines.append(f"  {BOLD}Technical category:{RESET} {tech}")
        lines.append(
            f"  {BOLD}Semantic type:     {RESET} {sem}  {GRAY}(confidence: {conf_label}){RESET}"
        )
        lines.append(f"  {BOLD}Snippet:{RESET}           {GRAY}{snip}{RESET}")
        lines.append("")
        lines.append(f"  {BOLD}Risks:{RESET}")
        for r in g["technical_risks"] + g["specific_risks"]:
            lines.append(f"    • {r}")
        lines.append(f"  {BOLD}Validation:{RESET}        {g['validation']}")
        if g["validation_regex"]:
            lines.append(f"  {BOLD}Validation regex:{RESET}  {GRAY}{g['validation_regex']}{RESET}")
        lines.append(f"  {BOLD}Sanitization:{RESET}      {g['sanitization']}")
        lines.append(f"  {BOLD}Why it matters:{RESET}    {g['threat_explanation']}")
        lines.append(f"  {GRAY}{'─' * 50}{RESET}")

        # Plain-text context for the host model — full operative guidance so the
        # LLM can act on the threat model, not just the label.
        regex_part = (
            f"Validation regex: {g['validation_regex']}. "
            if g["validation_regex"]
            else ""
        )
        context_parts.append(
            f"[USER INPUT DETECTED - Line {line}] "
            f"Category: {tech}, Type: {sem}, Severity: {g['severity']}. "
            f"Risks: {', '.join(g['technical_risks'] + g['specific_risks'])}. "
            f"Validation: {g['validation']}. "
            f"{regex_part}"
            f"Sanitization: {g['sanitization']}. "
            f"Threat model: {g['threat_explanation']}"
        )

        # Block reason for critical categories (first one wins).
        if tech in BLOCKING_CATEGORIES and not block_reason:
            block_reason = (
                f"⛔ BLOCKED: {tech} detected at line {line}.\n"
                f"Snippet: {snip}\n"
                f"Critical risk: {g['technical_risks'][0]}.\n"
                f"Required action: {g['sanitization']}\n"
                f"Fix this before proceeding. Then tell the user, in one sentence, that "
                f"VibeGate blocked this write ({tech}) and how you fixed it."
            )

    lines.append(
        f"{BOLD}{CYAN}  → {len(classified)} pattern(s) detected. "
        f"Review the security guidance above.{RESET}\n"
    )

    # Explicit instruction so the model surfaces the finding to the user
    # instead of silently acting on it — this matters most for warnings,
    # since a non-blocking finding doesn't otherwise interrupt the model's
    # flow or force it to explain anything.
    context_parts.append(
        "ACTION: Before finishing your reply, tell the user in one sentence that "
        "VibeGate flagged this (name the category above) and what you did about it."
    )

    return AnalysisResult(
        classified=classified,
        terminal_output="\n".join(lines),
        context_for_host="\n".join(context_parts),
        should_block=bool(block_reason),
        block_reason=block_reason,
    )
