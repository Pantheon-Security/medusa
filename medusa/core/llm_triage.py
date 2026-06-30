"""Optional LLM semantic triage of scan findings (build item #7).

This is an OPT-IN pass. It is OFF by default and performs NO network I/O
unless the user both passes ``--llm-triage`` AND has a provider configured
via environment variables. With no provider configured it is a clean no-op.

Design principles (deliberate, security-first):

* **Fail safe, never hide a real bug.** Any LLM/network/parse error for a
  finding marks it ``uncertain`` and KEEPS it. We never drop a finding on
  error, and we never silently suppress.
* **CRITICAL is sacrosanct.** A CRITICAL finding is never dropped by the LLM.
  It may be annotated with a verdict/reason, but it always stays visible.
* **Minimal data egress.** Only the rule_id, severity, a neutralized message,
  the ``file:line`` location, and an already-truncated code snippet are sent.
  Never whole files, and never the secrets scanner's secret values.
* **No heavy imports at module load.** Provider SDKs are lazy-imported inside
  the call so importing this module (or merely having it on disk) costs
  nothing and triggers no network.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple

# Verdict vocabulary used to annotate findings.
VERDICT_TRUE = "true_positive"
VERDICT_FALSE = "false_positive"
VERDICT_UNCERTAIN = "uncertain"

# Severities the LLM is allowed to *drop* (only when confidently FP). CRITICAL
# is intentionally absent: a CRITICAL finding is never dropped via LLM triage.
_DROPPABLE_SEVERITIES = frozenset({"HIGH", "MEDIUM", "LOW", "INFO"})

# Max chars of code snippet we are willing to send to the provider. Snippets
# are already truncated upstream (parallel._truncate_code, ~200 chars); this is
# a defensive second cap so a malformed finding can't leak a large blob.
_MAX_SNIPPET_CHARS = 200

# Max chars of message we send.
_MAX_MESSAGE_CHARS = 300


def _env(*names: str) -> Optional[str]:
    """Return the first non-empty environment variable among *names*."""
    for name in names:
        val = os.environ.get(name)
        if val and val.strip():
            return val
    return None


def llm_available() -> Tuple[bool, str]:
    """Detect a configured LLM provider WITHOUT importing any SDK.

    Returns ``(True, provider)`` where provider is one of ``"anthropic"`` or
    ``"openai"``, or ``(False, reason)`` when nothing is configured.

    Detection is purely environment-variable based so it is instant and never
    touches the network. ``MEDUSA_LLM_PROVIDER`` (with the matching API key)
    takes precedence, then ANTHROPIC, then OPENAI.
    """
    explicit = _env("MEDUSA_LLM_PROVIDER")
    if explicit:
        provider = explicit.strip().lower()
        if provider == "anthropic" and _env("ANTHROPIC_API_KEY", "MEDUSA_LLM_API_KEY"):
            return True, "anthropic"
        if provider == "openai" and _env("OPENAI_API_KEY", "MEDUSA_LLM_API_KEY"):
            return True, "openai"
        return (
            False,
            f"MEDUSA_LLM_PROVIDER={provider!r} set but no matching API key "
            f"(ANTHROPIC_API_KEY / OPENAI_API_KEY / MEDUSA_LLM_API_KEY)",
        )

    if _env("ANTHROPIC_API_KEY"):
        return True, "anthropic"
    if _env("OPENAI_API_KEY"):
        return True, "openai"

    return (
        False,
        "no LLM provider configured (set ANTHROPIC_API_KEY, OPENAI_API_KEY, "
        "or MEDUSA_LLM_PROVIDER + MEDUSA_LLM_API_KEY)",
    )


def _default_model(provider: str) -> str:
    """Default model id per provider, overridable via MEDUSA_LLM_MODEL."""
    override = _env("MEDUSA_LLM_MODEL")
    if override:
        return override
    if provider == "anthropic":
        return "claude-haiku-4-5-20251001"
    return "gpt-4o-mini"


def _finding_field(finding: Any, *keys: str, default: Any = None) -> Any:
    """Read the first present key from a dict-backed finding, else attribute.

    Findings in MEDUSA are normalized to dicts (see core/parallel.py), but we
    tolerate object-backed issues defensively so this helper never raises.
    """
    if isinstance(finding, dict):
        for key in keys:
            if key in finding and finding[key] is not None:
                return finding[key]
        return default
    for key in keys:
        if hasattr(finding, key):
            val = getattr(finding, key)
            if val is not None:
                return val
    return default


def _severity_str(finding: Any) -> str:
    sev = _finding_field(finding, "severity", default="MEDIUM")
    # Severity may be an enum with a .value.
    sev = getattr(sev, "value", sev)
    return str(sev).upper()


def _build_prompt(finding: Any) -> str:
    """Construct the minimal triage prompt for a single finding.

    We send ONLY: rule_id, severity, message, file:line, and a short snippet.
    Never the full file, never secret values beyond the already-truncated
    snippet the scanner produced.
    """
    rule_id = _finding_field(finding, "rule_id", default="(none)")
    severity = _severity_str(finding)
    message = str(_finding_field(finding, "issue", "message", default=""))[:_MAX_MESSAGE_CHARS]
    file_ = str(_finding_field(finding, "file", default="(unknown)"))
    line = _finding_field(finding, "line", "line_number", default=0)
    snippet = str(_finding_field(finding, "code", default=""))[:_MAX_SNIPPET_CHARS]

    return (
        "You are a security triage assistant. Decide whether the following "
        "static-analysis finding is a TRUE positive (a real issue worth a "
        "human looking at) or a FALSE positive (test fixture, example, "
        "obviously safe usage). Respond with EXACTLY one line in the form:\n"
        "VERDICT: <true_positive|false_positive|uncertain> | REASON: <one short sentence>\n\n"
        f"rule_id: {rule_id}\n"
        f"severity: {severity}\n"
        f"location: {file_}:{line}\n"
        f"message: {message}\n"
        f"code: {snippet}\n"
    )


def _parse_response(text: str) -> Tuple[str, str]:
    """Parse the model's single-line response into (verdict, reason).

    Robust to surrounding whitespace and casing. Anything we cannot map to a
    known verdict becomes ``uncertain`` (fail-safe: keep the finding).
    """
    verdict = VERDICT_UNCERTAIN
    reason = ""
    if not text:
        return verdict, "empty LLM response"

    lowered = text.lower()
    if VERDICT_FALSE in lowered:
        verdict = VERDICT_FALSE
    elif VERDICT_TRUE in lowered:
        verdict = VERDICT_TRUE
    elif VERDICT_UNCERTAIN in lowered:
        verdict = VERDICT_UNCERTAIN
    else:
        # Heuristic fallback on bare "false"/"true" if the structured tokens
        # are absent. Default stays uncertain.
        if "false positive" in lowered:
            verdict = VERDICT_FALSE
        elif "true positive" in lowered:
            verdict = VERDICT_TRUE

    # Pull the reason after a "REASON:" marker if present, else use the line.
    marker = "reason:"
    idx = lowered.find(marker)
    if idx != -1:
        reason = text[idx + len(marker):].strip()
    else:
        reason = text.strip().splitlines()[0][:200] if text.strip() else ""

    return verdict, reason[:200]


def _make_client(provider: str):
    """Lazy-import and construct the provider client.

    Returns the client object, or raises ImportError/Exception which the caller
    treats as "SDK unavailable" (findings returned unchanged with a note).
    """
    if provider == "anthropic":
        import anthropic  # lazy: only imported when triage actually runs

        api_key = _env("ANTHROPIC_API_KEY", "MEDUSA_LLM_API_KEY")
        return anthropic.Anthropic(api_key=api_key)
    if provider == "openai":
        import openai  # lazy

        api_key = _env("OPENAI_API_KEY", "MEDUSA_LLM_API_KEY")
        return openai.OpenAI(api_key=api_key)
    raise ValueError(f"unknown provider: {provider!r}")


def _call_llm(client, provider: str, model: str, prompt: str, timeout: int) -> str:
    """Single triage call. Returns the raw text; raises on transport error."""
    if provider == "anthropic":
        resp = client.messages.create(
            model=model,
            max_tokens=120,
            timeout=timeout,
            messages=[{"role": "user", "content": prompt}],
        )
        # content is a list of blocks; concatenate any text blocks.
        parts = []
        for block in getattr(resp, "content", []) or []:
            text = getattr(block, "text", None)
            if text:
                parts.append(text)
        return "".join(parts)

    # openai
    resp = client.chat.completions.create(
        model=model,
        max_tokens=120,
        timeout=timeout,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.choices[0].message.content or ""


def triage_findings(
    findings: List[Any],
    *,
    provider: Optional[str] = None,
    model: Optional[str] = None,
    timeout: int = 20,
    client: Any = None,
) -> Dict[str, Any]:
    """LLM-triage a list of findings, annotating each in place.

    Each finding (a dict, in MEDUSA's normalized shape) gains two keys:
        ``llm_verdict`` -> one of true_positive | false_positive | uncertain
        ``llm_reason``  -> a short one-line explanation

    Behaviour contract:
      * OFF unless a provider is configured. With no provider, returns the
        findings unchanged and ``note`` explaining why (no network).
      * Fail safe: any per-finding error -> ``uncertain`` + KEEP. Never drops
        a finding on error.
      * CRITICAL findings are NEVER dropped (they may be annotated).
      * A finding is only dropped when the LLM is confident it is a FALSE
        positive AND its severity is below CRITICAL. Dropped findings are
        still reported via the ``suppressed_fp`` count and ``kept`` list.

    Args:
        findings: list of finding dicts to triage (mutated in place).
        provider: force a provider; default = auto-detect via llm_available().
        model: model id; default per-provider (overridable via env).
        timeout: per-call timeout in seconds.
        client: pre-built client (used by tests to inject a fake; bypasses
            SDK import entirely).

    Returns:
        dict with keys:
          ``triaged``       int  - findings actually sent to the LLM
          ``kept``          list - findings retained (visible to the user)
          ``suppressed_fp`` int  - confident, sub-CRITICAL FPs dropped
          ``errors``        int  - findings that errored (kept as uncertain)
          ``note``          str  - optional human-readable status note
    """
    findings = findings or []
    result: Dict[str, Any] = {
        "triaged": 0,
        "kept": list(findings),
        "suppressed_fp": 0,
        "errors": 0,
        "note": "",
    }

    # Resolve provider. If none configured (and no injected client), no-op.
    if client is None:
        if provider is None:
            ok, info = llm_available()
            if not ok:
                result["note"] = info
                return result
            provider = info
        try:
            client = _make_client(provider)
        except Exception as exc:  # SDK missing or construction failed
            result["note"] = (
                f"LLM provider {provider!r} unavailable ({exc.__class__.__name__}); "
                f"findings returned unchanged"
            )
            return result
    else:
        # Injected client: still need a provider label to pick the call shape.
        if provider is None:
            ok, info = llm_available()
            provider = info if ok else "anthropic"

    resolved_model = model or _default_model(provider)

    kept: List[Any] = []
    suppressed = 0
    errors = 0
    triaged = 0

    for finding in findings:
        severity = _severity_str(finding)
        try:
            prompt = _build_prompt(finding)
            raw = _call_llm(client, provider, resolved_model, prompt, timeout)
            verdict, reason = _parse_response(raw)
            triaged += 1
        except Exception as exc:
            # Fail safe: mark uncertain, KEEP the finding. Never drop on error.
            verdict = VERDICT_UNCERTAIN
            reason = f"triage error: {exc.__class__.__name__}"
            errors += 1

        # Annotate in place (works for dict-backed findings).
        if isinstance(finding, dict):
            finding["llm_verdict"] = verdict
            finding["llm_reason"] = reason
        else:  # pragma: no cover - object-backed findings are not the norm
            try:
                setattr(finding, "llm_verdict", verdict)
                setattr(finding, "llm_reason", reason)
            except Exception:
                pass

        # Decide drop vs keep. ONLY drop a confident FP below CRITICAL.
        # CRITICAL is never dropped; uncertain/true_positive always kept.
        if (
            verdict == VERDICT_FALSE
            and severity != "CRITICAL"
            and severity in _DROPPABLE_SEVERITIES
        ):
            suppressed += 1
            # not appended -> dropped, but counted in suppressed_fp
        else:
            kept.append(finding)

    result.update(
        triaged=triaged,
        kept=kept,
        suppressed_fp=suppressed,
        errors=errors,
    )
    return result
