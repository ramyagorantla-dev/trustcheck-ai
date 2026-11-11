# TrustCheck: Final Report Outline
*Each section maps to a "Minimum Technical Requirement" in the assignment (R1–R11).*

## 1. Introduction
- Problem: phishing, smishing, fake job offers; why students are targeted.
- Goal and research questions:
  1. Does giving the LLM tools improve detection over the LLM alone?
  2. Does a larger model justify its extra latency/memory for this task?
  3. How robust is the system to prompt-injection attacks?

## 2. System architecture (R1, R2)
- Diagram from README. Explain the agent loop: reason → select tool → execute → observe → respond.
- Why an agent and not a fixed pipeline: different inputs need different checks (show a trace where an SMS skips header analysis and a job offer calls `check_job_offer`).
- Hybrid scoring (60/40) and why: the LLM handles meaning, tools give verifiable evidence.

## 3. Data (R3)
- Evaluation set: 42 synthetic messages, composition table (type × label × category); how they were written (from FTC/IC3 patterns); hard cases.
- Knowledge base for RAG: 12 scam-pattern sections, chunked by heading.
- Ethics of data: no real personal messages.

## 4. Prompt design and model configuration (R4)
- System prompt (quote it): untrusted-data tags, tool-selection guidance, "never say genuine", JSON schema.
- Model: qwen2.5:7b via Ollama, temperature 0.1, max 6 agent steps. Why Qwen2.5: native tool calling, runs on a laptop.
- Prompt iterations you tried and what changed (keep notes as you test!).

## 5. Evaluation methodology (R5, R6)
- Four systems, same test set. Metrics and why false-negative rate matters most.
- Model-size comparison (3B vs 7B): F1 vs latency vs RAM.
- Prompt-injection test cases.

## 6. Results
- `results/metrics.csv` table + `confusion_matrices.png`.
- Tools vs no tools; small vs large model; latency.

## 7. Success and failure analysis (R7)
- 3 successes with agent traces (screenshots from the app).
- 3–5 failures from `results/failures.md`, each with *why* (e.g. legit 2FA text flagged because it mentions "code"; BEC email passes SPF because it's a real Outlook account).

## 8. Limitations (R8)
See README. Add anything you observed.

## 9. Responsible AI, privacy, security (R9)
Local inference, no false reassurance, prompt-injection defense, explainability, misuse (could scammers use it to test their messages? mitigation: it's a detector, gives no rewriting help).

## 10. Demo (R10)
Live: the 4 built-in examples + upload `samples/` files. Back-up: a 3-minute screen recording.

## 11. Code and documentation (R11)
GitHub link, README, tests.

## 12. Conclusion and future work
Browser extension, multilingual support, more real data (UCI SMS spam), fine-tuning a small model.
