"""
LLM agent step. Calls a configured model provider to write the analyst-facing
summary, explanation, and next steps, grounded in the parsed alert, the rule
based score, and the MITRE lookup.

Safe by design: if Ollama is not running or times out, we fall back to a
clear rule based explanation so the app never breaks. This is the one LLM
step the course requires; everything feeding it is deterministic.

Supported providers are Ollama, Groq, and Gemini. If a provider is unavailable,
the rule-based fallback keeps the application usable.
"""
import json
import os
from typing import Dict

import requests
from dotenv import load_dotenv

from .rag import retrieve

load_dotenv()

LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "ollama").lower()
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/chat")
LLM_MODEL = os.environ.get(
    "LLM_MODEL",
    {"groq": "openai/gpt-oss-20b", "gemini": "gemini-2.0-flash"}.get(
        LLM_PROVIDER, "llama3.1:8b"
    ),
)
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models"
TIMEOUT = int(os.environ.get("LLM_TIMEOUT", "60"))

SYSTEM = (
    "You are a defensive SOC triage assistant. You help a Level 1 analyst. "
    "You never recommend offensive actions or anything that changes systems. "
    "Recommend only safe investigation steps (what to check, which logs to pull). "
    "Be concise and evidence based. Respond ONLY with valid JSON, no extra text."
)

PROMPT = """Analyze this security alert and respond with JSON only.

Alert:
- rule_name: {rule_name}
- host: {host}
- user: {user}
- source_ip: {src_ip}
- log_source: {log_source}
- raw_log: {raw_log}

Deterministic analysis already done (use it, do not contradict without reason):
- rule_based_priority: {priority} (score {score})
- rule_based_category: {category_guess}
- mitre_technique: {mitre_id} {mitre_name} ({mitre_tactic})

Retrieved knowledge (ground your answer in this and cite it):
{context}

Respond with exactly this JSON shape:
{{
  "summary": "one sentence plain-English summary of what happened",
  "priority": "Low|Medium|High|Critical",
  "priority_reason": "one sentence on why this priority",
  "next_steps": ["safe investigation step 1", "step 2", "step 3"]
}}"""


def llm_available() -> bool:
    """Quick check that the configured provider is usable."""
    try:
        if LLM_PROVIDER == "ollama":
            base = OLLAMA_URL.rsplit("/api/", 1)[0]
            requests.get(base + "/api/tags", timeout=3).raise_for_status()
            return True
        if LLM_PROVIDER == "groq":
            key = os.environ["GROQ_API_KEY"]
            requests.get(
                "https://api.groq.com/openai/v1/models",
                headers={"Authorization": "Bearer " + key},
                timeout=3,
            ).raise_for_status()
            return True
        if LLM_PROVIDER == "gemini":
            key = os.environ["GEMINI_API_KEY"]
            requests.get(GEMINI_URL, params={"key": key}, timeout=3).raise_for_status()
            return True
        return False
    except Exception:
        return False


def _fallback(enriched: Dict) -> Dict:
    """Rule based explanation used when the LLM is unavailable."""
    cat = enriched["category_guess"]
    steps_by_cat = {
        "credential_attack": ["Check whether any login eventually succeeded",
                              "Review other activity from this user and source IP",
                              "Confirm the account is not already compromised"],
        "lateral_movement": ["Identify the source host that initiated the connection",
                             "Check what ran on the destination host afterwards",
                             "Verify whether this admin/service account use was expected"],
        "ransomware": ["Isolate the host from the network for review",
                      "Check backups and shadow copies for integrity",
                      "Look for the initial access or dropper that preceded this"],
        "false_positive": ["Confirm the source matches a known scanner or admin task",
                           "Check the schedule or ticket that explains the activity"],
        "benign": ["No action needed; log for awareness"],
    }
    return {
        "summary": f"{enriched['rule_name']} on {enriched['host']} involving {enriched['user']}.",
        "priority": enriched["priority"],
        "priority_reason": "; ".join(enriched["reasons"][:2]),
        "next_steps": steps_by_cat.get(cat, ["Review the raw log and related events"]),
        "source": "rule_based_fallback (LLM unavailable)",
    }


def analyze_with_llm(enriched: Dict) -> Dict:
    """Ask the configured LLM to explain one alert. Falls back safely on any error.

    Retrieves relevant MITRE/playbook knowledge first (RAG) and grounds the
    explanation in it, returning the citations used.
    """
    query = f"{enriched['rule_name']} {enriched['raw_log']}"
    passages = retrieve(query, k=3)
    context = "\n".join(f"- [{p['source']}] {p['text']}" for p in passages)
    citations = [p["source"] for p in passages]
    prompt = PROMPT.format(
        rule_name=enriched["rule_name"], host=enriched["host"], user=enriched["user"],
        src_ip=enriched["src_ip"], log_source=enriched["log_source"],
        raw_log=enriched["raw_log"][:400], priority=enriched["priority"],
        score=enriched["score"], category_guess=enriched["category_guess"],
        mitre_id=enriched.get("mitre_id"), mitre_name=enriched.get("mitre_name"),
        mitre_tactic=enriched.get("mitre_tactic"),
        context=context,
    )
    try:
        messages = [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": prompt},
        ]
        if LLM_PROVIDER == "ollama":
            resp = requests.post(OLLAMA_URL, timeout=TIMEOUT, json={
                "model": LLM_MODEL, "stream": False, "format": "json",
                "messages": messages,
            })
            resp.raise_for_status()
            content = resp.json()["message"]["content"]
        elif LLM_PROVIDER == "groq":
            key = os.environ["GROQ_API_KEY"]
            resp = requests.post(
                GROQ_URL,
                timeout=TIMEOUT,
                headers={"Authorization": "Bearer " + key},
                json={"model": LLM_MODEL, "temperature": 0, "response_format": {"type": "json_object"},
                      "messages": messages},
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
        elif LLM_PROVIDER == "gemini":
            key = os.environ["GEMINI_API_KEY"]
            resp = requests.post(
                f"{GEMINI_URL}/{LLM_MODEL}:generateContent",
                params={"key": key},
                timeout=TIMEOUT,
                json={
                    "system_instruction": {"parts": [{"text": SYSTEM}]},
                    "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                    "generationConfig": {"responseMimeType": "application/json", "temperature": 0},
                },
            )
            resp.raise_for_status()
            content = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
        else:
            raise ValueError(f"Unsupported LLM_PROVIDER: {LLM_PROVIDER}")
        data = json.loads(content)
        data["source"] = f"LLM ({LLM_PROVIDER}/{LLM_MODEL})"
        data["citations"] = citations
        # keep the shape predictable
        data.setdefault("priority", enriched["priority"])
        data.setdefault("next_steps", [])
        return data
    except Exception as e:
        out = _fallback(enriched)
        out["source"] += f"  [reason: {type(e).__name__}]"
        out["citations"] = citations
        return out
