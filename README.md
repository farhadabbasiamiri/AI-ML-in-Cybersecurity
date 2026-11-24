# TriageMate

**SOC Alert Triage Agent** - a local AI agent that helps a security analyst sort a flood of alerts in minutes.

Group 1A capstone project, AI/ML in Cybersecurity, Laurentian University, Fall 2026.
**For defensive cybersecurity use only.**

---

## What it does

Security analysts receive far more alerts than they can read, and most are harmless. TriageMate does the first pass for them. An analyst loads a batch of SIEM alerts, and for each one the agent:

1. Summarizes what happened in plain English.
2. Maps it to a MITRE ATT&CK tactic and technique.
3. Assigns a risk score and priority, and explains why.
4. Recommends safe next investigation steps.

Nothing becomes a final ticket until the analyst approves it. The default is
local Ollama, but the project can also use a hosted Groq or Gemini model when
you do not want to download a multi-gigabyte local model.

---

## How it works

TriageMate uses a hybrid design. Plain Python always parses, scores, classifies,
and maps each alert before any model call, so the queue works even if the model
is offline. When analysis is requested, the app retrieves relevant knowledge
and sends the alert plus deterministic results to the configured LLM for an
analyst-facing explanation. The analyst approves before anything is finalized.

```
Upload alerts
      |
      v
Parser -> Rule scorer -> ML category model -> MITRE lookup
                         (always run locally; rule score remains the safety baseline)
      |
      v
Alert queue
      |
      v
Selected alert -> RAG retrieval -> Configured LLM
                 (Ollama, Groq, or Gemini; on demand)
      |
      v
Analyst review -> Approval gates -> Approved ticket (JSON)
                  (human in the loop)
```

If the LLM times out, is unavailable, or returns invalid data, the alert still
reaches the analyst with its deterministic results and a rule-based fallback
explanation, so the workflow does not stall.

---

## Project layout

```
triagemate/
  app.py                 Gradio web app (the interface)
  data/
    all_alerts.jsonl     110 alerts (synthetic + real OTRF + ransomware)
    all_labels.csv       answer key for evaluation
    generate_alerts.py   synthetic alert generator
    expand_dataset.py    dataset expansion helper
    DATA_CARD.md         where the data came from and its limits
  triage/
    parser.py            flattens raw alerts into standard fields
    scorer.py            rule based baseline severity scorer
    mitre.py             MITRE ATT&CK lookup tool
    ml_classifier.py     TF-IDF + Logistic Regression category model
    rag.py               playbook & MITRE RAG retriever (TF-IDF / optional Chroma)
    llm.py                 configured LLM agent with RAG grounding and safe fallback
    pipeline.py            load -> parse -> score -> ML category -> MITRE
    dashboard.py         dashboard metrics and charts
    knowledge/
      playbook.json      investigation playbook entries
      mitre_kb.json      MITRE ATT&CK knowledge base
  eval/
    evaluate.py          precision and recall against the answer key
  tests/
    test_pipeline.py     unit tests (pytest)
  requirements.txt
  LLM_SETUP.md           how to turn on the local LLM
  TECHNICAL_DOCUMENTATION.md
  WORKFLOW_EXPLANATION.md
  .env.example           copy to .env to change providers
```

---

## Setup

You need Python 3.10 or newer.

```bash
# 1. create a virtual environment inside the project folder
python -m venv .venv

# 2. activate it
source .venv/Scripts/activate      # Windows (Git Bash)
# .venv\Scripts\activate           # Windows (Command Prompt)
# source .venv/bin/activate        # Mac or Linux

# 3. install the libraries
pip install -r requirements.txt
```

You will know the environment is active when `(.venv)` appears at the start of your terminal line. Activate it again each time you open a new terminal.

---

## Run

```bash
python app.py
```

The terminal prints a local address such as `http://127.0.0.1:7860`. Open it in a browser. The interface has five tabs:

1. **Upload** - load a JSON Lines file, or leave it empty to use the built-in sample set, then click "Load and triage".
2. **Alert queue** - review all alerts sorted by rule priority and score. Run AI analysis over the highest-risk alerts when needed; rule-versus-AI disagreements are highlighted for review.
3. **Alert detail** - pick an alert to see deterministic results, MITRE mapping, reasons, and raw data. Click "Run AI analysis" for the grounded summary and safe next steps, with a trace of the parser, scorer, MITRE, RAG, and LLM steps.
4. **Approval & ticket** - run AI analysis, confirm analyst review, and approve an alert to create its structured JSON ticket. Recommended containment actions require a separate approval.
5. **Dashboard** - refresh summary metrics and charts for priorities, categories, MITRE techniques, rule-versus-AI results, and ticket approvals.

To stop the app, press Ctrl and C in the terminal.

The app uses a rule-based fallback if no provider is available. AI analysis is
run only for selected alerts or the requested queue limit; loading the queue
does not call the LLM. To configure a provider, see **LLM_SETUP.md**.

---

## Turning on an LLM provider

1. Keep the default local Ollama setup, or copy `.env.example` to `.env`.
2. For a no-download setup, select `LLM_PROVIDER=groq` or `LLM_PROVIDER=gemini`
   and add the corresponding API key.
3. Restart the app. The Upload tab status line will show the provider and
   whether it is online; the built-in fallback remains available offline.

Full details and troubleshooting are in **LLM_SETUP.md**. Keep Ollama bound to localhost, since its API has no authentication by default.

---

## Testing and evaluation

```bash
pytest                    # run the unit tests
python eval/evaluate.py   # measure accuracy against the answer key
```

The pipeline includes a supervised category model trained from
`data/all_labels.csv`: TF-IDF features with Logistic Regression. The model is
evaluated on a stratified held-out test split by `eval/evaluate.py`; the
rule-based category and priority scorer remains the safety baseline. The
evaluation also reports per-priority precision, recall, F1, and High/Critical
recall. Current results can change when the dataset changes, so use the
evaluation command for the latest numbers.

---

## Data

The dataset combines three sources: 100 synthetic alerts generated with a fixed seed, 4 real attack recordings from the OTRF Security-Datasets, and 6 ransomware alerts modelled on the splunk/attack_data datasets. Every alert carries a `data_source` field. Full detail, schema, and limitations are in **data/DATA_CARD.md**. All data is synthetic or from public research datasets; no real company logs or personal data are used.

---

## Safety boundaries

1. Defensive only. The agent recommends investigation steps and never acts on systems.
2. Human approval is required before any ticket is finalized; AI analysis must be run first.
3. Recommended containment actions require a separate analyst confirmation.
4. Synthetic and public research data only.
5. The local model stays bound to localhost.
6. No API keys or credentials are committed to the repository.
7. A single agent with deterministic tools, not a multi-agent system.

---

## Technology

Python, Gradio, scikit-learn (TF-IDF and Logistic Regression), Groq/Ollama/Gemini
LLM providers, a rule-based scorer, MITRE lookup, pandas, and pytest.

---

## Roadmap

1. Done: data pipeline, rule-based scorer, supervised ML category model, MITRE
   lookup, RAG playbook retrieval (built-in TF-IDF with optional Chroma),
   configurable LLM agent with fallback, queue-wide analysis, tool trace,
   Gradio dashboard, human and containment approval gates, tests, and evaluation.
2. Next: logging/monitoring, Docker packaging, and the final report and demo.

---

## Team

| Role | Owner |
| --- | --- |
| Project Lead and System Architect | |
| Data and ML Engineer | |
| AI Agent Developer | |
| Application Developer | |
| Testing and Security Engineer | |

Every member contributes code and can explain the full system.

---

## Acknowledgements

- MITRE ATT&CK, https://attack.mitre.org
- OTRF Security-Datasets, https://github.com/OTRF/Security-Datasets
- Splunk Attack Data, https://github.com/splunk/attack_data

Reference projects studied during design are credited in the final report.
