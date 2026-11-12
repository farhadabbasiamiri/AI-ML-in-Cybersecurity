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

TriageMate uses a hybrid design. Plain Python always parses and scores each alert first, so the app works even if the model is offline. A local LLM then adds reasoning and chooses which tools to run. The analyst approves before anything is finalized.

```
Upload alerts
      |
      v
Log parser  ->  Rule based scorer  ->  MITRE lookup     (always run, deterministic)
      |
      v
Configured LLM (Ollama, Groq, or Gemini) writes the explanation: (one LLM step)
   - MITRE lookup        tactic and technique
   - Ticket writer       structured JSON ticket
      |
      v
Analyst approval  ->  Approved ticket (JSON)            (human in the loop)
```

If the LLM times out or is not installed, the alert still reaches the analyst with its rule based score and a fallback explanation, so a demo never stalls.

---

## Project layout

```
triagemate/
  app.py                 Gradio web app (the interface)
  data/
    all_alerts.jsonl     110 alerts (synthetic + real OTRF + ransomware)
    all_labels.csv       answer key for evaluation
    generate_alerts.py   synthetic alert generator
    DATA_CARD.md         where the data came from and its limits
  triage/
    parser.py            flattens raw alerts into standard fields
    scorer.py            rule based baseline severity scorer
    mitre.py             MITRE ATT&CK lookup tool
    ml_classifier.py     TF-IDF + Logistic Regression category model
    llm.py               configured LLM agent with safe fallback
    pipeline.py          load -> parse -> score -> MITRE
  eval/
    evaluate.py          precision and recall against the answer key
  tests/
    test_pipeline.py     unit tests (pytest)
  requirements.txt
  LLM_SETUP.md           how to turn on the local LLM
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

The terminal prints a local address such as `http://127.0.0.1:7860`. Open it in a browser. The interface has four tabs:

1. **Upload** - load a JSON Lines file, or leave it empty to use the built in sample set, then click "Load and triage".
2. **Alert queue** - all alerts sorted by risk, most serious at the top.
3. **Alert detail** - pick an alert to see its score, MITRE mapping, and reasons. Click "Run AI analysis" for the LLM summary and next steps, with a tool trace of each step the agent took.
4. **Approval and ticket** - approve an alert to create its JSON ticket.

To stop the app, press Ctrl and C in the terminal.

The app uses a rule-based fallback if no provider is available. To enable AI
analysis, see **LLM_SETUP.md**.

---

## Turning on an LLM provider

1. Keep the default Ollama setup, or copy `.env.example` to `.env`.
2. For a no-download setup, select `LLM_PROVIDER=groq` or `LLM_PROVIDER=gemini`
   and add the corresponding API key.
3. Restart the app. The Upload tab status line will show the provider status.

Full details and troubleshooting are in **LLM_SETUP.md**. Keep Ollama bound to localhost, since its API has no authentication by default.

---

## Testing and evaluation

```bash
pytest                    # run the unit tests
python eval/evaluate.py   # measure accuracy against the answer key
```

The pipeline includes a supervised category model trained from
`data/all_labels.csv`: TF-IDF features with Logistic Regression. The model is
evaluated on a held-out test split by `eval/evaluate.py`; the rule-based
category and priority scorer remains the safety baseline. Current results can
change when the dataset changes, so use the evaluation command for the latest
numbers.

---

## Data

The dataset combines three sources: 100 synthetic alerts generated with a fixed seed, 4 real attack recordings from the OTRF Security-Datasets, and 6 ransomware alerts modelled on the splunk/attack_data datasets. Every alert carries a `data_source` field. Full detail, schema, and limitations are in **data/DATA_CARD.md**. All data is synthetic or from public research datasets; no real company logs or personal data are used.

---

## Safety boundaries

1. Defensive only. The agent recommends investigation steps and never acts on systems.
2. Human approval is required before any ticket is finalized.
3. Synthetic and public research data only.
4. The local model stays bound to localhost.
5. No API keys or credentials are committed to the repository.
6. A single agent with a few tools, not a multi agent system.

---

## Technology

Python, Gradio, scikit-learn (TF-IDF and Logistic Regression), Groq/Ollama/Gemini
LLM providers, a rule-based scorer, MITRE lookup, pandas, and pytest.

---

## Roadmap

1. Done: data pipeline, rule-based scorer, supervised ML category model, MITRE
   lookup, configurable LLM agent with fallback, Gradio interface, human
   approval, tests, and evaluation.
2. Next: RAG playbook retrieval with Chroma to ground the explanations in written investigation guidance.
3. Then: logging and monitoring tab, failure handling tests, Docker packaging, and the final report and demo.

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
