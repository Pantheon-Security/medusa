"""Gate for the last agent-reach CRITICAL — OWASP prompt-injection must not fire on a
plain f-string status/print containing `{message}` (PC001 handover 2026-07-22-fp-realworld).

Ground truth (agent-reach cli.py:296):
    print(f"  ✅ {platform}: {message}")     # a console status print, not an LLM prompt
owasp_llm_scanner's LLM01 pattern matched any f-string containing `{message}` with NO LLM
context, so ordinary print/log lines were flagged CRITICAL "User input interpolated in
prompt string". `message` is far too generic (status/log/print everywhere). The genuine
user-data indicators (user_input|request|query) stay; real LLM-context prompt injection is
covered by the context-aware PromptInjectionCodeScanner (PIC001-008).
"""
import re

from medusa.scanners.owasp_llm_scanner import OWASPLLMScanner


def _prompt_injection_patterns():
    return [p for p, _ in OWASPLLMScanner.PROMPT_INJECTION_PATTERNS]


def _fires(text):
    return any(p.search(text) for p in _prompt_injection_patterns())


def test_print_fstring_with_message_not_flagged():
    for benign in ('print(f"  ✅ {platform}: {message}")',
                   'logger.info(f"done: {message}")',
                   'print(f"status {message} ok")'):
        assert not _fires(benign), f"a plain f-string print must NOT be prompt-injection: {benign!r}"


def test_real_prompt_injection_still_flagged():
    for real in ('prompt = f"You are a helpful assistant. User says: {user_input}"',
                 'f"Answer the {query} now"',
                 'system = f"context: {request}"'):
        assert _fires(real), f"real user-input interpolation must still fire: {real!r}"
