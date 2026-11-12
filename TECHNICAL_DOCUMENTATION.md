# TriageMate - Technical Documentation

Group 1A, AI/ML in Cybersecurity, Laurentian University, Fall 2026.
This document explains how the whole system works, so any team member can
understand, run, extend, and present it. Read it top to bottom once.

---

## 1. What the project is

TriageMate is a defensive AI agent that triages security alerts. An analyst loads
a batch of SIEM alerts; for each one the agent summarises it, maps it to a MITRE
ATT&CK technique, scores its risk, explains why, cites supporting knowledge, and
recommends safe next steps. A human approves before any ticket is finalised.
The deterministic pipeline runs locally. The LLM can use local Ollama or the
optional hosted Groq/Gemini providers; hosted providers require an API key and
should only receive synthetic or approved data.

---

## 2. The big picture (how one alert flows through the system)

```
                 data/all_alerts.jsonl  (real, referenced alerts)
                              |
                              v
   [1] parser.py      normalise the raw alert into flat fields
                              |
                              v
   [2] scorer.py      rule-based risk score + category baseline (always runs)
                              |
                              v
   [3] ml_classifier.py  TF-IDF + Logistic Regression category prediction
                              |
                              v
   [4] mitre.py       map the alert to a MITRE ATT&CK technique (always runs)
                              |
                              v
   [5] rag.py         retrieve relevant ATT&CK + playbook knowledge (always runs)
                              |
                              v
   [6] llm.py         configured LLM writes summary, priority reason, safe steps,
                      grounded in the retrieved knowledge, with citations
                      (falls back to rules if the LLM is offline)
                              |
                              v
   [7] app.py         analyst reviews everything, then APPROVES
                              |
                              v
                      JSON ticket (priority, MITRE, summary, steps, citations)
```

Steps 1 to 5 run locally before the LLM request. The ML model is trained from
the labelled training data and then performs local inference; the rule-based
scorer remains the safety baseline. The LLM is the explanation layer and
degrades safely. This is the "hybrid" design: reliable core, intelligent layer
on top.

---

## 3. The files, one by one

### Data
- `data/all_alerts.jsonl` - 53 real alerts, one JSON object per line. No answer
  labels inside, because the agent should not see the answers.
- `data/all_labels.csv` - the answer key (alert_id, category, priority), used only
  for evaluation.
- `data/DATA_CARD.md` - where every alert came from, with a full reference table.

### The triage package (`triage/`)
- `parser.py` - `parse_alert()` flattens a raw alert (nested JSON) into standard
  fields, filling missing values safely so nothing crashes.
- `scorer.py` - `score_alert()` gives each alert a rule-based score, priority, and
  category guess, with the reasons. This is the baseline and the safety net.
- `ml_classifier.py` - trains a TF-IDF plus Logistic Regression category
  classifier from labelled alerts. It returns an ML category and confidence;
  it does not replace the rule-based priority scorer.
- `mitre.py` - `mitre_lookup()` maps an alert's text to a MITRE ATT&CK technique
  by keyword.
- `rag.py` - the retriever. Builds a knowledge base from the ATT&CK subset and the
  SOC playbook, then returns the most relevant passages for an alert. Two backends
  (see section 5).
- `llm.py` - `analyze_with_llm()` calls the configured Ollama, Groq, or Gemini
  model to write the analyst-facing summary, priority reason, and next steps,
  grounded in the retrieved knowledge. Falls back to rules if the provider is
  unavailable.
- `pipeline.py` - ties steps 1 to 4 together and produces the sorted alert queue.
- `knowledge/mitre_kb.json` - the ATT&CK technique descriptions (the RAG source).
- `knowledge/playbook.json` - the SOC investigation playbook (the other RAG source).

### Application and support
- `app.py` - the Gradio interface (four tabs).
- `eval/evaluate.py` - measures accuracy against the answer key.
- `tests/test_pipeline.py` - unit tests (run with `pytest`).

---

## 4. Supervised ML category model

The project uses `data/all_labels.csv` as training ground truth. The model
combines `rule_name`, `raw_log`, `log_source`, and `data_source` into text,
converts that text into TF-IDF features, and trains multiclass Logistic
Regression with balanced class weights. For each alert it returns:

- `ml_category` - the predicted alert category
- `ml_confidence` - the predicted class probability

The rule-based `category_guess` remains visible as a transparent baseline, and
the rule-based score remains responsible for priority. This prevents the ML
model from silently changing the safety-critical prioritization logic.

`eval/evaluate.py` trains the classifier only on the training portion and
reports results on a stratified held-out test portion. This prevents training
data from being used as evidence of generalization. The current dataset has
188 labelled alerts, with 47 held out for testing; run the command again after
changing data to regenerate the metrics.

## 5. What makes this a real agent (not just a classifier)

The course guide is explicit: a UI wired to one classifier is not an agent. The
agent must select and run tools, interpret the results, and respond. In TriageMate:

- The deterministic tools (parser, scorer, MITRE lookup, RAG retriever) are real
  Python tools with clear inputs and outputs.
- The LLM receives the alert plus the tool outputs and the retrieved knowledge,
  and produces a grounded decision with citations.
- The tool trace panel in the UI shows every tool that ran and what it returned,
  so a reviewer can verify the workflow.

---

## 5. How RAG works here (the part that grounds the answers)

RAG means Retrieval Augmented Generation. Instead of letting the LLM answer from
memory, we store reference knowledge and retrieve the relevant pieces for each
alert, then hand them to the LLM. This keeps answers accurate and lets us cite
sources.

Knowledge base = MITRE ATT&CK technique descriptions (`mitre_kb.json`) plus the
SOC playbook (`playbook.json`).

Two retriever backends, chosen automatically in `rag.py`:
1. Chroma + sentence-transformers embeddings (semantic search). Used if those
   libraries are installed and a model is available.
2. A built-in TF-IDF cosine retriever in pure Python. No downloads, always works.
   This is the default and the fallback, so the demo never breaks.

TF-IDF in one line: it scores how important each word is (rare words matter more),
represents the alert and each knowledge passage as weighted word vectors, and
returns the passages whose vectors are most similar to the alert.

To switch backends: set the environment variable `RAG_BACKEND=tfidf` to force the
built-in one, or install chromadb and sentence-transformers to enable semantic
search. The UI shows which backend is active.

---

## 6. How the LLM step works (and why it is safe)

`llm.py` calls the configured provider. Before calling, it retrieves knowledge
(RAG) and puts it in the prompt, asking the model to ground its answer and
respond in strict JSON. If the provider is unavailable, times out, or errors,
the code catches it and returns a rule-based explanation instead, still with
citations. So the app always produces a result. The UI labels whether the
answer came from the LLM or the fallback.

To enable the real LLM, configure `.env` as described in `LLM_SETUP.md`, then
start the app.

---

## 7. The data: where it comes from and how it was built

All 53 alerts are real events from the two sources in the course resources:
- OTRF Security-Datasets (https://github.com/OTRF/Security-Datasets)
- Splunk Attack Data (https://github.com/splunk/attack_data)

Each source recording contains thousands of mixed events. For every dataset we
extracted the single event that reveals the technique (for example, the process
that accesses LSASS, or the command that deletes shadow copies). Benign and
false-positive alerts are real background events from the same recordings. Every
alert keeps a `data_source` reference to its exact origin. Full detail and the
reference table are in `data/DATA_CARD.md`.

Labelling note: the source (where it came from) is a verifiable fact. Attack
labels come from the known technique of each dataset. Benign and false-positive
labels are team judgement on real events, documented openly.

---

## 8. How to run everything

```bash
# one-time setup (inside the project folder)
python -m venv .venv
source .venv/Scripts/activate      # Windows Git Bash; see README for other shells
pip install -r requirements.txt

# run the app
python app.py                      # open the local URL it prints

# run the evaluation
python eval/evaluate.py

# run the tests
pytest
```

Enabling the local LLM and semantic RAG is optional and covered in `LLM_SETUP.md`
and section 5. The app works without either, using the fallbacks.

---

## 9. Evaluation and what the numbers mean

`eval/evaluate.py` compares the pipeline's output to the answer key and reports
category accuracy and per-priority precision and recall. On the real data the
rule-based baseline is deliberately modest, because real logs are hard for simple
rules. This is the point: it is the baseline the LLM agent is measured against, so
improvement from the agent is the core evidence in the report. Always report the
baseline first, then the agent, then the difference.

---

## 10. Who owns what (team roles)

- Project Lead / System Architect: scope, architecture, GitHub, documentation.
- Data / ML Engineer: the dataset, schema, baseline scorer, and the RAG knowledge.
- AI Agent Developer: the LLM integration, prompts, and tool calling.
- Application Developer: the Gradio interface and packaging.
- Testing / Security Engineer: tests, evaluation, failure handling, and safety.

Everyone should be able to explain sections 2, 4, and 5 in the presentation.

---

## 11. What is done and what is next

Done: data pipeline, rule-based scorer, MITRE lookup, RAG retriever with citations,
local LLM agent with safe fallback, Gradio interface with tool trace, human
approval, tests, evaluation.

Next: a logging/monitoring tab, failure-handling tests, Docker packaging, and the
final report and demo script.
