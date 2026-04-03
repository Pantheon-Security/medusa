We've been building quietly. Here's what MEDUSA became in 2026.
At the start of this year, MEDUSA had 180 AI security rules and 73 scanners.

We just shipped v2026.3.1.

Here's what changed:

**Rules: 180 → 3,200+**
We rebuilt the detection engine from scratch. Prompt injection, RAG poisoning, MCP vulnerabilities, agent attacks, training data exploitation, supply chain risks — patterns across the entire modern AI stack, not just Python code.

**False positives: decimated**
508 false positive filters. 96.8% FP reduction rate. Security tools that cry wolf get ignored. We obsessed over precision.

**CVEs: 0 → 380**
Created a new CVE tracking system for AI/ML CVEs across NVD, EUVD, OSV, and GitHub Advisory. This week alone, we added 32 new ones — vLLM RCE, Keras path traversal, MLflow SSRF, LlamaIndex SQL injection. Most teams don't know these exist in their stack.

New attack surfaces covered:

 - MCP server vulnerabilities (400+ patterns)
 - UCP, AP2, ACP agent protocols (91 dedicated rules)
 - RAG pipeline & dataset poisoning (300+ patterns)
 - 133 critical CVE version detections

52% faster than v2026.1. Multi-core parallel scanning, single-pass file discovery, pre-compiled patterns.

And it's still just:
pip install medusa-security
medusa scan .

Free. Open source. No API keys, no config, no setup.

If you're shipping AI applications in 2026 and you're not scanning for these attack vectors — you should be.

👉 github.com/Pantheon-Security/medusa 