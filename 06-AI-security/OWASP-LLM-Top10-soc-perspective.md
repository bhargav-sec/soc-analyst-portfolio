# OWASP Top 10 For LLMs — A SOC Analyst's Perspective

**Focus:** Mapping LLM-specific threats to SOC detection, triage, and response workflows.

## Why This Matters for SOC Analysts

Enterprises are rapidly deploying LLM-powered applications — internal chatbots, code assistants, RAG-based knowledge tools, customer-facing agents. Each deployment creates new attack surfaces that traditional SIEM rules and EDR signatures don't cover. As a SOC analyst, understanding the OWASP LLM Top 10 is the first step toward building detection logic for AI-era threats.

This write-up walks through the OWASP Top 10 for LLM Applications (2025 edition) and maps each risk to practical SOC detection and response ideas.

## The OWASP LLM Top 10 — 2025

### LLM01: Prompt Injection
**What it is:** An attacker crafts input that manipulates the LLM into ignoring its system prompt and following attacker instructions. Two flavours:
- **Direct injection** — attacker types malicious prompt directly
- **Indirect injection** — attacker plants malicious instructions in data the LLM later ingests (emails, webpages, PDFs)

**SOC detection angle:**
- Log all LLM prompts + responses (like you'd log queries to a database)
- Detect suspicious patterns: "ignore previous instructions", "you are now...", "system override"
- Monitor for unexpected tool/function calls from the LLM (e.g., email-sending agent suddenly trying to access internal wiki)
- Anomaly detection on prompt length, language mix, or encoding (base64 payloads)

### LLM02: Sensitive Information Disclosure
**What it is:** LLM leaks training data, system prompts, or information from previous users.

**SOC detection angle:**
- DLP rules on LLM outputs — regex for PII, API keys, internal hostnames, internal project names
- Monitor for prompts asking the model to "repeat its instructions" or "print system prompt"
- Correlate multi-turn conversations where user appears to be probing for memorized training data

### LLM03: Supply Chain Vulnerabilities
**What it is:** Compromised pre-trained models, poisoned datasets, malicious LoRAs or plugins from HuggingFace / public repos.

**SOC detection angle:**
- Maintain an inventory of which models are deployed where (AI BOM)
- Monitor integrity hashes of model files at runtime
- Block model downloads from non-approved sources via egress proxy rules

### LLM04: Data & Model Poisoning
**What it is:** Attacker injects malicious content into training or fine-tuning data to create backdoors or bias model outputs.

**SOC detection angle:**
- Alert on unusual data ingestion paths feeding training pipelines
- Baseline model behaviour on a test set — alert when output distribution drifts
- Monitor fine-tuning job metadata (who, when, what data)

### LLM05: Improper Output Handling
**What it is:** Application trusts LLM output and passes it directly to downstream systems (SQL, shell, browser) — classic injection vectors, but now the LLM is the attacker's proxy.

**SOC detection angle:**
- Treat LLM output as untrusted user input
- Log and alert on LLM responses containing SQL keywords, shell commands, script tags
- Correlate LLM output events with downstream system logs (e.g., suspicious query to database 200ms after an LLM response)

### LLM06: Excessive Agency
**What it is:** LLM-based agents given too many tools / permissions. Attacker uses prompt injection to abuse legitimate capabilities (send emails, execute code, modify files).

**SOC detection angle:**
- Map each agent's tool permissions — smallest footprint possible
- Alert on agent actions outside baselined normal (agent that usually reads files suddenly writes to `/etc/`)
- Rate-limit high-impact tools (email send, payment, file delete)

### LLM07: System Prompt Leakage
**What it is:** Attacker extracts the system prompt, revealing business logic, internal APIs, or hidden instructions.

**SOC detection angle:**
- Fingerprint known system-prompt extraction techniques and alert
- Do not store sensitive secrets in system prompts in the first place — if the prompt leaks, secrets leak

### LLM08: Vector & Embedding Weaknesses
**What it is:** RAG (retrieval-augmented generation) systems that pull in attacker-controlled documents get poisoned — attacker plants a document in the vector DB that the LLM later retrieves and "trusts."

**SOC detection angle:**
- Treat vector DB ingestion as a trust boundary; log what gets indexed, by whom
- Monitor for unusual retrieval patterns (same obscure document retrieved dozens of times)
- Detect embedded instructions in ingested documents before indexing

### LLM09: Misinformation
**What it is:** LLM confidently generates wrong information — hallucinations. If users or downstream systems trust the output, this becomes a security issue (fake CVEs, fake URLs that attackers then register, fake package names used in code).

**SOC detection angle:**
- Validate package names / URLs / CVEs emitted by code-generating LLMs against authoritative sources before execution
- Alert on "slopsquatting" — attackers registering hallucinated package names to compromise supply chains

### LLM10: Unbounded Consumption
**What it is:** Denial-of-wallet / denial-of-service — attacker sends huge or recursive prompts to drive up inference cost or exhaust the service.

**SOC detection angle:**
- Rate limit per user / API key
- Alert on prompt length outliers, recursive generation patterns, cost anomalies on the LLM provider bill
- Monitor token consumption as a first-class signal (like network bytes)

## How I'd Bring LLM Telemetry into a SOC

Traditional SOCs watch network, endpoint, and identity logs. An LLM-era SOC needs three additional telemetry streams:

1. **Prompt logs** — every user input to the model (sanitized for sensitive data)
2. **Response logs** — every model output, including any tool calls / function invocations
3. **Agent action logs** — structured events for each tool an LLM agent uses (file read, email sent, API called)

All three should feed into the SIEM (Splunk, Sentinel, QRadar) and be correlated with traditional telemetry — a prompt injection that leads to email exfiltration should show as a single investigation, not three disconnected alerts.

## MITRE ATLAS Mapping

MITRE ATLAS is the "MITRE ATT&CK for AI systems." Some relevant techniques:

| OWASP Risk | MITRE ATLAS Technique |
|---|---|
| LLM01 Prompt Injection | AML.T0051 (LLM Prompt Injection) |
| LLM02 Info Disclosure | AML.T0057 (LLM Data Leakage) |
| LLM04 Data Poisoning | AML.T0020 (Poison Training Data) |
| LLM06 Excessive Agency | AML.T0053 (LLM Plugin Compromise) |
| LLM08 Vector Weaknesses | AML.T0070 (RAG Poisoning) |

## Takeaways for a SOC Team Just Starting with AI

1. **Log first, detect second** — you can't build rules without telemetry. Establish LLM logging before worrying about detection content.
2. **Treat LLM output as untrusted input** — the same discipline applied to user input in web apps.
3. **Map every agent's tools** — the blast radius of an excessive-agency compromise equals the sum of the agent's permissions.
4. **Cost anomalies are a security signal** — unexpected inference spend often means someone is abusing the system.
5. **The attack surface is the prompt, not the network** — classical NIDS/EDR won't catch prompt injection. Application-layer visibility is mandatory.

## References
- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)

---
*Research and analysis write-up — no live investigation. Intended to demonstrate understanding of AI/LLM security threats as they relate to SOC operations.*
