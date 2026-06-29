#!/usr/bin/env python3
"""
Shared ML / AI / inference content-applicability gate.

Several MEDUSA scanners load large harvested YAML rule corpora that are
*AI-specific by definition* — adversarial-ML / model-poisoning rules
(ModelAttackScanner), OWASP LLM Top-10 rules (OWASPLLMScanner), and the
inference-infrastructure harvest (LLMOpsScanner). Many of those harvested rules
match very generic tokens and fire on plain non-AI code (requests / urllib3 /
jinja2 / rich), producing the bulk of those scanners' false positives.

This module provides a single, conservative *applicability gate*: report a
scanner's AI-specific YAML rules ONLY when the file shows genuine ML / AI / LLM /
inference context. A real attack in an AI-context file (one that imports
torch / transformers / langchain / openai / ... or serves a model) still carries
that context, so it still fires — coverage is preserved and no rule is removed.

Design notes:
  * Word boundaries keep `serve` / `triton` / `ray` / `llm` from matching inside
    unrelated identifiers (`observe`, `nutrition`, `array`, `library`, ...).
  * The token list is deliberately broad on the AI/ML side (coverage-first): we
    would rather keep an AI signal and accept a rare benign match than drop a
    framework token and miss a real attack in code that uses it.
"""

import re

# Single source of truth for "does this file do ML / AI / LLM / inference work?".
# Case-insensitive; matched against full file content.
_ML_CONTEXT_RE = re.compile(
    r'\b(?:'
    # --- ML / DL frameworks and runtimes ---
    r'torch|pytorch|tensorflow|tf\.keras|keras|jax|flax|sklearn'
    r'|scikit[_-]?learn|xgboost|lightgbm|catboost|onnx|onnxruntime'
    r'|transformers|huggingface|hugging_face|sentence_transformers'
    r'|diffusers|accelerate|peft|bitsandbytes|safetensors'
    # --- Inference servers / serving stacks ---
    r'|vllm|tensorrt|triton(?:server|_inference)?|tritonclient'
    r'|text_generation|tgi|ollama|llama_cpp|llama\.cpp|ctransformers'
    r'|torchserve|tfserving|tf_serving|bentoml|seldon|kserve|kfserving'
    r'|ray\.serve|rayserve|litserve|mlserver'
    # --- Experiment / model lifecycle / registries ---
    r'|mlflow|wandb|weights_and_biases|sagemaker|vertexai|vertex_ai'
    r'|kubeflow|clearml|comet_ml|dvc|model_registry|modelregistry'
    # --- LLM / agent SDKs and providers ---
    r'|langchain|llama_index|llamaindex|openai|anthropic|cohere|mistral'
    r'|groq|litellm|tiktoken|semantic_kernel|promptflow|chainlit|instructor'
    r'|dspy|guidance|autogen|crewai|haystack'
    r'|chatgpt|claude|gemini|gpt-?[34]|chat\.completions'
    r'|HumanMessage|SystemMessage|AIMessage|ChatOpenAI|ChatAnthropic'
    r'|PromptTemplate|LLMChain|ConversationChain'
    # --- Generic but ML-anchored serving / inference / model phrasing ---
    r'|model_serving|model_server|inference_server|inference_engine'
    r'|inference_endpoint|model_endpoint|predict_endpoint'
    r'|serve_model|load_model|model_load|from_pretrained|pretrained'
    r'|AutoModel|AutoTokenizer|AutoConfig|nn\.Module|fine[_-]?tune|fine[_-]?tuning'
    r'|adversarial|model_inversion|membership_inference|model_extraction'
    r'|embeddings?|vector_store|vectorstore|faiss|pinecone|chromadb|qdrant'
    r'|weaviate|milvus'
    r'|llm|chat_completion|completion\(|prompt_template|system_prompt'
    r')\b',
    re.IGNORECASE,
)


# Emoji-dictionary data line, e.g. `"gemini": "♊",` or `"hugging_face": "🤗",`.
# Several AI/ML names (gemini, claude, mistral, bert, hugging_face, ...) collide
# with emoji-code dictionary KEYS in pure data files like rich/_emoji_codes.py.
# Those are data, not AI code, and were the single largest residual FP source for
# the AI scanners. A line is an emoji-dict datum when it is a quoted key mapped to
# a quoted value that contains a non-ASCII (emoji/glyph) character. We strip such
# lines before testing for ML context so the dict keys can't fake an AI signal.
# This NEVER hides real code: `import openai`, `openai.chat.completions(...)`, etc.
# are not quoted-key→emoji-value pairs.
_EMOJI_DICT_LINE_RE = re.compile(
    r'^\s*["\'][\w\- ]+["\']\s*:\s*["\'][^"\']*[^\x00-\x7f][^"\']*["\']\s*,?\s*$'
)


def has_ml_context(content: str) -> bool:
    """True when the file shows genuine ML / AI / LLM / inference context.

    Used to gate AI-specific YAML rule corpora so their generic harvest patterns
    do not fire on benign non-AI code (network / template / utility libraries).

    Emoji-dictionary data lines (quoted-name -> emoji-glyph) are stripped first so
    that AI/ML names colliding with emoji codes (gemini, claude, hugging_face, ...)
    in pure data files do not fake an AI signal. Real AI code is unaffected.
    """
    # Fast path: if no emoji-prone token is present at all, skip the line strip.
    if not _ML_CONTEXT_RE.search(content):
        return False

    # Re-test against the content with emoji-dict data lines removed. Only pay the
    # per-line cost when a candidate token exists AND the file actually contains a
    # non-ASCII char (emoji dicts always do; ordinary code usually doesn't).
    if any(ord(ch) > 127 for ch in content):
        scrubbed = '\n'.join(
            ln for ln in content.splitlines()
            if not _EMOJI_DICT_LINE_RE.match(ln)
        )
        return bool(_ML_CONTEXT_RE.search(scrubbed))

    return True
