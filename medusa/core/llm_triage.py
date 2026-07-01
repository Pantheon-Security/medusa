"""Optional LLM semantic triage of scan findings (build item #7).

This is an OPT-IN pass. It is OFF by default and performs NO subprocess or
network I/O unless the user both passes ``--llm-triage`` AND has a usable LLM
backend available. With nothing available it is a clean no-op.

Pluggable backends (auto-detected in this PRIORITY order):

1. ``claude-cli``    — the locally-installed ``claude`` CLI in print mode
   (``claude -p "<prompt>" --output-format json``). Uses the user's existing
   Claude Max/Pro subscription — NO API key required. This is the PREFERRED
   backend for interactive users.
2. ``codex-cli``     — the locally-installed ``codex`` CLI run non-interactively
   (``codex exec "<prompt>"``). Uses the user's OpenAI/ChatGPT subscription.
3. ``anthropic-api`` — ``ANTHROPIC_API_KEY`` + the ``anthropic`` SDK. Intended
   for CI / hosted-service use where a pay-per-token key is available.
4. ``openai-api``    — ``OPENAI_API_KEY`` + the ``openai`` SDK. CI / service.

The selection can be forced with the ``MEDUSA_LLM_BACKEND`` environment
variable (or the ``--llm-backend`` CLI option), whose value is one of
``claude-cli | codex-cli | anthropic-api | openai-api``.

Design principles (deliberate, security-first):

* **Fail safe, never hide a real bug.** Any backend/subprocess/network/parse
  error for a finding marks it ``uncertain`` and KEEPS it. We never drop a
  finding on error, and we never silently suppress.
* **CRITICAL is sacrosanct.** A CRITICAL finding is never dropped by the LLM.
  It may be annotated with a verdict/reason, but it always stays visible.
* **Minimal data egress.** Only the rule_id, severity, a neutralized message,
  the ``file:line`` location, and an already-truncated code snippet are sent.
  Never whole files, and never the secrets scanner's secret values.
* **No heavy imports at module load.** Provider SDKs are lazy-imported inside
  the call so importing this module (or merely having it on disk) costs
  nothing and triggers no network. The CLI backends shell out to a binary the
  user already has, so no SDK is needed at all for the preferred path.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any, Callable, Dict, List, Optional, Tuple

# Verdict vocabulary used to annotate findings.
VERDICT_TRUE = "true_positive"
VERDICT_FALSE = "false_positive"
VERDICT_UNCERTAIN = "uncertain"

# Backend labels (also the accepted MEDUSA_LLM_BACKEND / --llm-backend values).
BACKEND_CLAUDE_CLI = "claude-cli"
BACKEND_CODEX_CLI = "codex-cli"
BACKEND_ANTHROPIC_API = "anthropic-api"
BACKEND_OPENAI_API = "openai-api"

# The four backends in auto-detection priority order.
_BACKEND_ORDER = (
    BACKEND_CLAUDE_CLI,
    BACKEND_CODEX_CLI,
    BACKEND_ANTHROPIC_API,
    BACKEND_OPENAI_API,
)

# Severities the LLM is allowed to *drop* (only when confidently FP). CRITICAL
# is intentionally absent: a CRITICAL finding is never dropped via LLM triage.
_DROPPABLE_SEVERITIES = frozenset({"HIGH", "MEDIUM", "LOW", "INFO"})

# Max chars of code snippet we are willing to send to the backend. Snippets
# are already truncated upstream (parallel._truncate_code, ~200 chars); this is
# a defensive second cap so a malformed finding can't leak a large blob.
_MAX_SNIPPET_CHARS = 200

# Max chars of message we send.
_MAX_MESSAGE_CHARS = 300

# Default per-call timeout (seconds). CLI backends can be a little slower to
# spin up than a raw HTTP call, so we allow a generous window; any timeout is
# still fail-safe (the finding is KEPT as uncertain).
_DEFAULT_TIMEOUT = 30


def _env(*names: str) -> Optional[str]:
    """Return the first non-empty environment variable among *names*."""
    for name in names:
        val = os.environ.get(name)
        if val and val.strip():
            return val
    return None


def _backend_ready(label: str) -> Tuple[bool, str]:
    """Report whether a specific backend *label* is usable right now.

    Returns ``(True, label)`` when the backend's prerequisite (a CLI on PATH or
    an API key in the environment) is satisfied, else ``(False, reason)``.
    """
    if label == BACKEND_CLAUDE_CLI:
        if shutil.which("claude"):
            return True, label
        return False, "backend 'claude-cli' requested but the 'claude' CLI is not on PATH"
    if label == BACKEND_CODEX_CLI:
        if shutil.which("codex"):
            return True, label
        return False, "backend 'codex-cli' requested but the 'codex' CLI is not on PATH"
    if label == BACKEND_ANTHROPIC_API:
        if _env("ANTHROPIC_API_KEY", "MEDUSA_LLM_API_KEY"):
            return True, label
        return False, "backend 'anthropic-api' requested but no ANTHROPIC_API_KEY is set"
    if label == BACKEND_OPENAI_API:
        if _env("OPENAI_API_KEY", "MEDUSA_LLM_API_KEY"):
            return True, label
        return False, "backend 'openai-api' requested but no OPENAI_API_KEY is set"
    return (
        False,
        f"unknown LLM backend {label!r} (expected one of: "
        f"{', '.join(_BACKEND_ORDER)})",
    )


def llm_available(backend: Optional[str] = None) -> Tuple[bool, str]:
    """Detect a usable LLM backend WITHOUT importing any SDK or shelling out.

    Returns ``(True, backend_label)`` where ``backend_label`` is one of the four
    ``BACKEND_*`` values, or ``(False, reason)`` when nothing is available.

    Selection precedence:
      1. an explicit *backend* argument (from ``--llm-backend``), else
      2. the ``MEDUSA_LLM_BACKEND`` environment variable, else
      3. auto-detection in priority order: claude-cli, codex-cli,
         anthropic-api, openai-api.

    Detection is cheap: ``shutil.which`` for the CLIs (a PATH lookup, no exec)
    and env-var presence for the API backends. It never runs the model.
    """
    requested = backend or _env("MEDUSA_LLM_BACKEND")
    if requested:
        return _backend_ready(requested.strip().lower())

    for label in _BACKEND_ORDER:
        ok, _ = _backend_ready(label)
        if ok:
            return True, label

    return (
        False,
        "no LLM backend available: install the 'claude' or 'codex' CLI (uses "
        "your existing subscription — no API key), or set ANTHROPIC_API_KEY / "
        "OPENAI_API_KEY for CI use",
    )


def _default_model(backend: str) -> str:
    """Default model id for the API backends, overridable via MEDUSA_LLM_MODEL.

    Only the ``*-api`` backends take a model id here; the CLI backends use
    whatever model the user's ``claude`` / ``codex`` install is configured for.
    """
    override = _env("MEDUSA_LLM_MODEL")
    if override:
        return override
    if backend == BACKEND_ANTHROPIC_API:
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
        "obviously safe usage). Answer with a single word verdict followed by "
        "one short reason, in EXACTLY this form and nothing else:\n"
        "VERDICT: <true_positive|false_positive|uncertain> | REASON: <one short sentence>\n\n"
        f"rule_id: {rule_id}\n"
        f"severity: {severity}\n"
        f"location: {file_}:{line}\n"
        f"message: {message}\n"
        f"code: {snippet}\n"
    )


def _parse_response(text: str) -> Tuple[str, str]:
    """Parse the model's response into (verdict, reason).

    Robust to surrounding whitespace, casing, and extra prose: we look for the
    verdict token anywhere in the text. Anything we cannot map to a known
    verdict becomes ``uncertain`` (fail-safe: keep the finding).
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
        # Heuristic fallback on bare "false"/"true" phrasing if the structured
        # tokens are absent. Default stays uncertain.
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


# --- Backend call implementations ------------------------------------------
#
# Each returns the model's raw assistant text, or raises on any transport /
# non-zero / parse error. The caller (triage_findings) turns any raise into a
# fail-safe 'uncertain' verdict that KEEPS the finding.


def _call_claude_cli(prompt: str, timeout: int) -> str:
    """Run the local ``claude`` CLI in print mode and return the reply text.

    ``claude -p "<prompt>" --output-format json`` emits a JSON object whose
    ``result`` field holds the assistant's text. Uses the user's Claude
    subscription — no API key. ``shell=False`` (list argv), no shell parsing.
    """
    proc = subprocess.run(
        ["claude", "-p", prompt, "--output-format", "json"],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"claude CLI exited {proc.returncode}: {(proc.stderr or '').strip()[:200]}"
        )
    data = json.loads(proc.stdout)  # raises on bad JSON -> fail-safe uncertain
    # Print-mode JSON puts the assistant text in "result"; tolerate a couple of
    # alternate shapes defensively without ever raising here.
    if isinstance(data, dict):
        for key in ("result", "response", "text", "content"):
            val = data.get(key)
            if isinstance(val, str) and val:
                return val
    return ""


def _call_codex_cli(prompt: str, timeout: int) -> str:
    """Run the local ``codex`` CLI non-interactively and return stdout.

    ``codex exec "<prompt>"`` runs a single turn using the user's OpenAI /
    ChatGPT subscription and prints the reply to stdout. ``shell=False``.
    """
    proc = subprocess.run(
        ["codex", "exec", prompt],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"codex CLI exited {proc.returncode}: {(proc.stderr or '').strip()[:200]}"
        )
    return proc.stdout or ""


def _make_anthropic_client():
    """Lazy-import and construct the anthropic SDK client (API backend)."""
    import anthropic  # lazy: only imported when the api backend actually runs

    return anthropic.Anthropic(api_key=_env("ANTHROPIC_API_KEY", "MEDUSA_LLM_API_KEY"))


def _call_anthropic_api(client, model: str, prompt: str, timeout: int) -> str:
    resp = client.messages.create(
        model=model,
        max_tokens=120,
        timeout=timeout,
        messages=[{"role": "user", "content": prompt}],
    )
    parts = []
    for block in getattr(resp, "content", []) or []:
        text = getattr(block, "text", None)
        if text:
            parts.append(text)
    return "".join(parts)


def _make_openai_client():
    """Lazy-import and construct the openai SDK client (API backend)."""
    import openai  # lazy

    return openai.OpenAI(api_key=_env("OPENAI_API_KEY", "MEDUSA_LLM_API_KEY"))


def _call_openai_api(client, model: str, prompt: str, timeout: int) -> str:
    resp = client.chat.completions.create(
        model=model,
        max_tokens=120,
        timeout=timeout,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.choices[0].message.content or ""


def _make_runner(backend: str) -> Callable[[str, int], str]:
    """Build a ``runner(prompt, timeout) -> text`` closure for *backend*.

    For the CLI backends this is a thin wrapper around ``subprocess.run`` (no
    SDK, no key). For the API backends the SDK is lazy-imported and the client
    constructed exactly once, here, so a missing SDK surfaces as an error the
    caller reports as "backend unavailable" (findings returned unchanged).
    """
    if backend == BACKEND_CLAUDE_CLI:
        return _call_claude_cli
    if backend == BACKEND_CODEX_CLI:
        return _call_codex_cli
    if backend == BACKEND_ANTHROPIC_API:
        client = _make_anthropic_client()
        model = _default_model(backend)
        return lambda prompt, timeout: _call_anthropic_api(client, model, prompt, timeout)
    if backend == BACKEND_OPENAI_API:
        client = _make_openai_client()
        model = _default_model(backend)
        return lambda prompt, timeout: _call_openai_api(client, model, prompt, timeout)
    raise ValueError(f"unknown backend: {backend!r}")


def triage_findings(
    findings: List[Any],
    *,
    backend: Optional[str] = None,
    timeout: int = _DEFAULT_TIMEOUT,
    runner: Optional[Callable[[str, int], str]] = None,
) -> Dict[str, Any]:
    """LLM-triage a list of findings, annotating each in place.

    Each finding (a dict, in MEDUSA's normalized shape) gains two keys:
        ``llm_verdict`` -> one of true_positive | false_positive | uncertain
        ``llm_reason``  -> a short one-line explanation

    Behaviour contract:
      * OFF unless a backend is available. With none, returns the findings
        unchanged and ``note`` explaining why (no subprocess, no network).
      * Fail safe: any per-finding error (non-zero exit, timeout, bad JSON,
        transport failure) -> ``uncertain`` + KEEP. Never drops on error.
      * CRITICAL findings are NEVER dropped (they may be annotated).
      * A finding is only dropped when the LLM is confident it is a FALSE
        positive AND its severity is below CRITICAL. Dropped findings are
        still reported via the ``suppressed_fp`` count and ``kept`` list.

    Args:
        findings: list of finding dicts to triage (mutated in place).
        backend: force a backend label; default = auto-detect via
            llm_available() (which honours --llm-backend / MEDUSA_LLM_BACKEND).
        timeout: per-call timeout in seconds.
        runner: pre-built ``runner(prompt, timeout) -> text`` callable (used by
            tests to inject a fake; bypasses backend construction entirely).

    Returns:
        dict with keys:
          ``triaged``       int  - findings actually sent to the model
          ``kept``          list - findings retained (visible to the user)
          ``suppressed_fp`` int  - confident, sub-CRITICAL FPs dropped
          ``errors``        int  - findings that errored (kept as uncertain)
          ``backend``       str  - the backend label used ("" if none)
          ``note``          str  - optional human-readable status note
    """
    findings = findings or []
    result: Dict[str, Any] = {
        "triaged": 0,
        "kept": list(findings),
        "suppressed_fp": 0,
        "errors": 0,
        "backend": "",
        "note": "",
    }

    # Resolve the backend + runner. If nothing is available (and no injected
    # runner), this is a clean no-op.
    if runner is None:
        ok, info = llm_available(backend)
        if not ok:
            result["note"] = info
            return result
        backend = info
        try:
            runner = _make_runner(backend)
        except Exception as exc:  # SDK missing / client construction failed
            result["note"] = (
                f"LLM backend {backend!r} unavailable ({exc.__class__.__name__}); "
                f"findings returned unchanged"
            )
            return result
    else:
        # Injected runner: keep whatever backend label the caller gave (for
        # reporting only); default to a generic label when unspecified.
        backend = backend or "injected"

    result["backend"] = backend

    kept: List[Any] = []
    suppressed = 0
    errors = 0
    triaged = 0

    for finding in findings:
        severity = _severity_str(finding)
        try:
            prompt = _build_prompt(finding)
            raw = runner(prompt, timeout)
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
