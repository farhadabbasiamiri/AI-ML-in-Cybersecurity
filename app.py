"""
SOC Alert Triage Agent (MVP)

Deterministic pipeline (parse + rule score + MITRE lookup) runs on load.
The LLM agent (local, via Ollama) runs on demand in the Alert Detail tab and
writes the summary, priority reason, and safe next steps. If Ollama is not
running, a rule based fallback is used so the demo never breaks.

Run:  python app.py   then open the local URL it prints.
Optional LLM:  install Ollama, then  ollama pull llama3.1:8b
"""
import json
import time

import gradio as gr
import pandas as pd

from triage.pipeline import load_alerts, triage_all, PRIORITY_RANK
from triage.llm import LLM_PROVIDER, analyze_with_llm, llm_available
from triage.rag import retrieve, backend_name
from triage import dashboard as dash

DEFAULT_DATA = "data/all_alerts.jsonl"
PRIORITY_EMOJI = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
STATE = {"df": None, "approved": set(), "analysis": {}}


def build_queue(file_obj):
    path = file_obj.name if file_obj else DEFAULT_DATA
    try:
        df = triage_all(load_alerts(path))
    except Exception as e:
        return None, f"Could not read alerts: {e}", gr.update(choices=[]), gr.update(choices=[])
    STATE["df"] = df
    STATE["approved"] = set()
    STATE["analysis"] = {}
    view = df[["alert_id", "priority", "score", "category_guess",
               "mitre_id", "rule_name", "host"]].copy()
    view.insert(0, "", view["priority"].map(PRIORITY_EMOJI))
    choices = df["alert_id"].tolist()
    online = "online" if llm_available() else "offline (fallback will be used)"
    msg = (f"Loaded {len(df)} alerts. {df['priority'].value_counts().to_dict()}  "
           f"| LLM provider: {LLM_PROVIDER} ({online}) | RAG: {backend_name()}")
    first = choices[0] if choices else None
    return view, msg, gr.update(choices=choices, value=first), gr.update(choices=choices, value=first)


def _queue_view():
    """Build the queue table showing rule priority next to AI priority and a one-line summary,
    sorted by the higher of the two priorities."""
    df = STATE["df"]
    rows = []
    for _, r in df.iterrows():
        aid = r["alert_id"]
        a = STATE.get("analysis", {}).get(aid, {})
        ai_prio = a.get("priority", "")
        summary = a.get("summary", "")
        rule_rank = PRIORITY_RANK.get(r["priority"], 9)
        ai_rank = PRIORITY_RANK.get(ai_prio, 9)
        sort_rank = min(rule_rank, ai_rank)  # higher severity = lower number
        disagree = "yes" if ai_prio and ai_prio != r["priority"] else ""
        rows.append({
            "": PRIORITY_EMOJI.get(r["priority"], ""),
            "alert_id": aid,
            "rule_priority": r["priority"],
            "ai_priority": ai_prio or "-",
            "disagree": disagree,
            "category": r["category_guess"],
            "mitre": r["mitre_id"] or "-",
            "summary": (summary[:80] + "...") if len(summary) > 80 else summary,
            "_sort": sort_rank,
            "_score": int(r["score"]),
        })
    vdf = pd.DataFrame(rows).sort_values(["_sort", "_score"], ascending=[True, False])
    return vdf.drop(columns=["_sort", "_score"]).reset_index(drop=True)


def run_ai_over_queue(limit, progress=gr.Progress()):
    """Run the LLM over the top `limit` alerts by rule score, caching results.
    Returns the enriched queue view."""
    df = STATE["df"]
    if df is None:
        return None, "Load alerts first."
    limit = int(limit)
    # process highest rule-score alerts first
    order = df.sort_values("score", ascending=False)["alert_id"].tolist()
    todo = [a for a in order if a not in STATE.get("analysis", {})][:limit]
    STATE.setdefault("analysis", {})
    STATE.setdefault("rag", {})
    for aid in progress.tqdm(todo, desc="Running AI over queue"):
        row = df[df["alert_id"] == aid].iloc[0].to_dict()
        STATE["rag"][aid] = retrieve(f"{row['rule_name']} {row['raw_log']}", k=3)
        STATE["analysis"][aid] = analyze_with_llm(row)
    done = len(STATE["analysis"])
    disagreements = sum(1 for _, r in df.iterrows()
                        if STATE["analysis"].get(r["alert_id"], {}).get("priority")
                        and STATE["analysis"][r["alert_id"]]["priority"] != r["priority"])
    msg = (f"AI analysis complete for {done} of {len(df)} alerts. "
           f"Rule vs AI disagreements: {disagreements} (these are the rows worth reviewing).")
    return _queue_view(), msg


def show_detail(alert_id):
    df = STATE["df"]
    if df is None or not alert_id:
        return "Load alerts and pick one from the queue.", ""
    row = df[df["alert_id"] == alert_id].iloc[0]
    reasons = "\n".join(f"  - {r}" for r in row["reasons"])
    mitre = (f"{row['mitre_id']} {row['mitre_name']} ({row['mitre_tactic']})"
             if row["mitre_id"] else "No confident match")
    approved = "APPROVED" if alert_id in STATE["approved"] else "awaiting approval"

    # show any LLM analysis already run for this alert
    llm_block = "_Click 'Run AI analysis' to add the LLM summary and next steps._"
    if alert_id in STATE["analysis"]:
        a = STATE["analysis"][alert_id]
        steps = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(a.get("next_steps", [])))
        cites = "\n".join(f"  - {c}" for c in a.get("citations", [])) or "  - (none)"
        llm_block = (f"**AI summary:** {a.get('summary','')}\n\n"
                     f"**AI priority:** {a.get('priority','')} - {a.get('priority_reason','')}\n\n"
                     f"**Recommended safe next steps:**\n{steps}\n\n"
                     f"**Sources cited (RAG):**\n{cites}\n\n"
                     f"_source: {a.get('source','')}_")

    # retrieved knowledge passages (shown once AI analysis has run)
    rag_block = ""
    hits = STATE.get("rag", {}).get(alert_id)
    if hits:
        parts = []
        for h in hits:
            parts.append(f"**{h['source']}** (match {h['score']})\n\n> {h['text']}")
        rag_block = "\n\n**Retrieved knowledge used to ground the analysis:**\n\n" + "\n\n".join(parts)

    detail = f"""### {PRIORITY_EMOJI[row['priority']]} {row['alert_id']} - {row['priority']} (score {row['score']})

**Rule:** {row['rule_name']}
**Baseline category:** {row['category_guess']}
**MITRE ATT&CK:** {mitre}
**Host:** {row['host']}   **User:** {row['user']}
**Source IP:** {row['src_ip']}   **Log source:** {row['log_source']}
**Data source:** {row['data_source']}

**Why this score (rule based):**
{reasons}

**Raw log:**
```
{row['raw_log'][:500]}
```

---
{llm_block}
{rag_block}

**Ticket status:** {approved}
"""
    return detail, ""


def run_ai(alert_id):
    """Run the LLM step for one alert and show a tool trace."""
    df = STATE["df"]
    if df is None or not alert_id:
        return "Load alerts and pick one first.", ""
    row = df[df["alert_id"] == alert_id].iloc[0].to_dict()

    trace = []
    t0 = time.time()
    trace.append(f"[parser]  normalized alert {alert_id}")
    trace.append(f"[scorer]  rule score={row['score']} priority={row['priority']}")
    trace.append(f"[mitre]   {row['mitre_id']} {row['mitre_name']}")
    hits = retrieve(f"{row['rule_name']} {row['raw_log']}", k=3)
    STATE.setdefault("rag", {})[alert_id] = hits
    trace.append(f"[rag]     retrieved {len(hits)} passages via {backend_name()}:")
    for h in hits:
        trace.append(f"            - {h['score']} {h['source']}")
    trace.append(f"[llm]     calling local model...")
    analysis = analyze_with_llm(row)
    STATE["analysis"][alert_id] = analysis
    trace.append(f"[llm]     done in {time.time()-t0:.1f}s  source={analysis.get('source')}")
    detail, _ = show_detail(alert_id)
    return detail, "\n".join(trace)


CONTAINMENT_WORDS = ("isolate", "contain", "disable", "quarantine", "block", "shut down", "shutdown")


def needs_containment_approval(alert_id) -> bool:
    """True if this alert's recommended next steps mention a containment action."""
    a = STATE.get("analysis", {}).get(alert_id, {})
    text = " ".join(a.get("next_steps", [])).lower() + " " + a.get("priority_reason", "").lower()
    return any(w in text for w in CONTAINMENT_WORDS)


def refresh_approval_controls(alert_id):
    """Reset the confirm boxes when the selected alert changes."""
    return (gr.update(value=False),   # reset confirm checkbox
            gr.update(value=False),    # reset containment checkbox (always visible)
            "")                        # clear previous ticket output


def approve(alert_id, confirmed, containment_ok):
    if STATE["df"] is None or not alert_id:
        return "Nothing to approve yet. Load alerts and select one."
    # Gate 1: analyst must confirm
    if not confirmed:
        return "Approval blocked: tick the confirmation checkbox before approving."
    # Gate 2: if AI analysis was never run, do not allow a ticket
    if alert_id not in STATE.get("analysis", {}):
        return "Approval blocked: run AI analysis on this alert before approving the ticket."
    # Gate 3: containment actions need their own approval
    if needs_containment_approval(alert_id) and not containment_ok:
        return ("Approval blocked: the recommended steps include a containment action "
                "(for example isolate or disable). Tick the containment approval checkbox to proceed.")

    STATE["approved"].add(alert_id)
    row = STATE["df"][STATE["df"]["alert_id"] == alert_id].iloc[0]
    analysis = STATE["analysis"].get(alert_id, {})
    ticket = {
        "alert_id": alert_id, "priority": row["priority"], "score": int(row["score"]),
        "category": row["category_guess"],
        "mitre": {"id": row["mitre_id"], "name": row["mitre_name"]},
        "rule_name": row["rule_name"], "host": row["host"],
        "ai_summary": analysis.get("summary", ""),
        "next_steps": analysis.get("next_steps", []),
        "citations": analysis.get("citations", []),
        "containment_approved": bool(containment_ok) if needs_containment_approval(alert_id) else "n/a",
        "approved_by": "analyst",
    }
    return "Ticket approved and created:\n\n```json\n" + json.dumps(ticket, indent=2) + "\n```"


def refresh_dashboard():
    """Rebuild all dashboard charts and the metrics text from current state."""
    df = STATE["df"]
    analysis = STATE.get("analysis", {})
    approved = STATE.get("approved", set())
    return (dash.metrics_text(df, analysis, approved),
            dash.priority_chart(df),
            dash.category_chart(df),
            dash.mitre_chart(df),
            dash.rule_vs_ai_chart(df, analysis),
            dash.approval_chart(df, approved))


with gr.Blocks(title="SOC Alert Triage Agent") as demo:
    gr.Markdown("# SOC Alert Triage Agent\nDefensive use only.")

    with gr.Tab("1. Upload"):
        up = gr.File(label="Upload alerts (JSON Lines). Leave empty to use the sample set.")
        load_btn = gr.Button("Load and triage", variant="primary")
        load_msg = gr.Markdown()

    with gr.Tab("2. Alert queue"):
        with gr.Row():
            queue_n = gr.Slider(5, 188, value=30, step=5, label="How many alerts to run the AI over (highest risk first)")
            run_queue_btn = gr.Button("Run AI over queue", variant="primary")
        queue_msg = gr.Markdown()
        queue = gr.Dataframe(label="Rule priority vs AI priority (disagreements are worth reviewing)", interactive=False)

    with gr.Tab("3. Alert detail"):
        picker = gr.Dropdown(label="Select an alert", choices=[])
        ai_btn = gr.Button("Run AI analysis", variant="primary")
        detail = gr.Markdown()
        gr.Markdown("**Tool trace** (shows the agent's steps):")
        trace_out = gr.Textbox(label="", lines=6, interactive=False)

    with gr.Tab("4. Approval & ticket"):
        approve_picker = gr.Dropdown(label="Alert to approve", choices=[])
        gr.Markdown("_Run AI analysis on the alert first. Then confirm below to create the ticket._")
        confirm_box = gr.Checkbox(label="I have reviewed this alert and approve creating a ticket.", value=False)
        containment_box = gr.Checkbox(
            label="I also approve any recommended CONTAINMENT action (isolate/disable/etc.), if applicable.",
            value=False, visible=True)
        approve_btn = gr.Button("Approve ticket", variant="primary")
        ticket_out = gr.Markdown()

    with gr.Tab("5. Dashboard"):
        gr.Markdown("Analytics across the current alert queue. Click Refresh after loading or running AI.")
        dash_refresh = gr.Button("Refresh dashboard", variant="primary")
        dash_metrics = gr.Markdown()
        with gr.Row():
            dash_priority = gr.Plot(label="By priority")
            dash_category = gr.Plot(label="By category")
        with gr.Row():
            dash_mitre = gr.Plot(label="MITRE techniques")
            dash_rule_ai = gr.Plot(label="Rule vs AI")
        with gr.Row():
            dash_approval = gr.Plot(label="Approvals")

    load_btn.click(build_queue, inputs=up, outputs=[queue, load_msg, picker, approve_picker])
    run_queue_btn.click(run_ai_over_queue, inputs=queue_n, outputs=[queue, queue_msg])
    picker.change(show_detail, inputs=picker, outputs=[detail, trace_out])
    ai_btn.click(run_ai, inputs=picker, outputs=[detail, trace_out])
    approve_picker.change(refresh_approval_controls, inputs=approve_picker,
                          outputs=[confirm_box, containment_box, ticket_out])
    approve_btn.click(approve, inputs=[approve_picker, confirm_box, containment_box], outputs=ticket_out)
    dash_refresh.click(refresh_dashboard, inputs=None,
                       outputs=[dash_metrics, dash_priority, dash_category, dash_mitre, dash_rule_ai, dash_approval])

if __name__ == "__main__":
    demo.launch()