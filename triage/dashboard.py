"""
Analytics dashboard charts for the SOC Alert Triage Agent.

Builds matplotlib figures from the current triaged queue and any AI analysis
that has been run. Each function returns a Figure that Gradio renders. Charts:
  1. Alerts by priority
  2. Alerts by category
  3. Top MITRE ATT&CK techniques
  4. Rule priority vs AI priority (shows where the agent adds value)
  5. Approved vs pending tickets
"""
from collections import Counter

import matplotlib
matplotlib.use("Agg")  # no display needed
import matplotlib.pyplot as plt

PRIORITY_ORDER = ["Critical", "High", "Medium", "Low"]
PRIORITY_COLOR = {"Critical": "#c0392b", "High": "#e67e22", "Medium": "#f1c40f", "Low": "#27ae60"}
ACCENT = "#2e5aac"


def _blank(msg):
    fig, ax = plt.subplots(figsize=(4, 3))
    ax.text(0.5, 0.5, msg, ha="center", va="center", fontsize=10, color="#666")
    ax.axis("off")
    return fig


def priority_chart(df):
    if df is None or len(df) == 0:
        return _blank("Load alerts first")
    counts = Counter(df["priority"])
    labels = [p for p in PRIORITY_ORDER if counts.get(p, 0) > 0]
    values = [counts[p] for p in labels]
    colors = [PRIORITY_COLOR[p] for p in labels]
    fig, ax = plt.subplots(figsize=(4, 3))
    bars = ax.bar(labels, values, color=colors)
    ax.bar_label(bars, padding=2, fontsize=9)
    ax.set_title("Alerts by priority (rule based)", fontsize=11)
    ax.set_ylabel("Count")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    return fig


def category_chart(df):
    if df is None or len(df) == 0:
        return _blank("Load alerts first")
    counts = Counter(df["category_guess"])
    items = counts.most_common()
    labels = [k for k, _ in items]
    values = [v for _, v in items]
    fig, ax = plt.subplots(figsize=(4, 3))
    bars = ax.barh(labels[::-1], values[::-1], color=ACCENT)
    ax.bar_label(bars, padding=2, fontsize=9)
    ax.set_title("Alerts by category", fontsize=11)
    ax.set_xlabel("Count")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    return fig


def mitre_chart(df):
    if df is None or len(df) == 0:
        return _blank("Load alerts first")
    counts = Counter(str(t) for t in df["mitre_id"] if t and str(t) != "nan")
    items = counts.most_common(8)
    if not items:
        return _blank("No MITRE techniques mapped")
    labels = [k for k, _ in items]
    values = [v for _, v in items]
    fig, ax = plt.subplots(figsize=(4, 3))
    bars = ax.barh(labels[::-1], values[::-1], color="#6c5ce7")
    ax.bar_label(bars, padding=2, fontsize=9)
    ax.set_title("Top MITRE ATT&CK techniques", fontsize=11)
    ax.set_xlabel("Count")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    return fig


def rule_vs_ai_chart(df, analysis):
    if df is None or len(df) == 0:
        return _blank("Load alerts first")
    if not analysis:
        return _blank("Run AI over the queue\nto compare rule vs AI")
    rule_counts = Counter()
    ai_counts = Counter()
    for _, r in df.iterrows():
        a = analysis.get(r["alert_id"])
        if not a:
            continue
        rule_counts[r["priority"]] += 1
        ai_counts[a.get("priority", "?")] += 1
    labels = PRIORITY_ORDER
    rule_vals = [rule_counts.get(p, 0) for p in labels]
    ai_vals = [ai_counts.get(p, 0) for p in labels]
    x = range(len(labels))
    fig, ax = plt.subplots(figsize=(4, 3))
    ax.bar([i - 0.2 for i in x], rule_vals, width=0.4, label="Rule", color="#95a5a6")
    ax.bar([i + 0.2 for i in x], ai_vals, width=0.4, label="AI", color=ACCENT)
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.set_title("Rule vs AI priority (analyzed alerts)", fontsize=11)
    ax.set_ylabel("Count")
    ax.legend(fontsize=8)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    return fig


def approval_chart(df, approved):
    if df is None or len(df) == 0:
        return _blank("Load alerts first")
    n_appr = len(approved)
    n_pending = len(df) - n_appr
    fig, ax = plt.subplots(figsize=(4, 3))
    bars = ax.bar(["Approved", "Pending"], [n_appr, n_pending],
                  color=["#27ae60", "#bdc3c7"])
    ax.bar_label(bars, padding=2, fontsize=9)
    ax.set_title("Tickets approved vs pending", fontsize=11)
    ax.set_ylabel("Count")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    return fig


def metrics_text(df, analysis, approved):
    if df is None or len(df) == 0:
        return "Load alerts to see metrics."
    counts = Counter(df["priority"])
    crit_high = counts.get("Critical", 0) + counts.get("High", 0)
    analyzed = len(analysis) if analysis else 0
    disagree = sum(1 for _, r in df.iterrows()
                   if analysis and analysis.get(r["alert_id"], {}).get("priority")
                   and analysis[r["alert_id"]]["priority"] != r["priority"]) if analysis else 0
    return (f"### Queue summary\n"
            f"- Total alerts: **{len(df)}**\n"
            f"- Critical + High (need attention): **{crit_high}**\n"
            f"- AI analyzed: **{analyzed}** of {len(df)}\n"
            f"- Rule vs AI disagreements: **{disagree}**\n"
            f"- Tickets approved: **{len(approved)}**")