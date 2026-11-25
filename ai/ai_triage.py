#!/usr/bin/env python3
"""
AI-assisted alert triage for the SOC home lab (100% free option: local LLM via Ollama).

Flow:  Splunk detection (.spl) -> results (Splunk REST API or exported JSON) -> redaction
       -> LLM (triage summary, ATT&CK mapping, next steps) -> markdown report
       -> ANALYST validates against raw logs (the AI never closes an alert).

LAB DATA ONLY. The default provider is a local model, so logs never leave your machine.

Providers (set LLM_PROVIDER):
    ollama     (default, free)  needs Ollama running locally, e.g.  ollama pull llama3.2:3b
    anthropic  (paid API key)   needs ANTHROPIC_API_KEY

Examples (PowerShell):
    # Live from Splunk, password auth (no token needed)
    $env:SPLUNK_URL="https://<WIN10_IP>:8089"; $env:SPLUNK_USER="admin"; $env:SPLUNK_PASSWORD="<pw>"
    python ai_triage.py ..\\detections\\01_bruteforce_failed_logons.spl --earliest -4h

    # Offline: use a JSON export of the Splunk results (Export > JSON in Splunk)
    python ai_triage.py ..\\detections\\01_bruteforce_failed_logons.spl --from-json results.json
"""
import argparse
import datetime
import json
import os
import re
import sys
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings()  # lab Splunk uses a self-signed certificate

SPLUNK_URL = os.environ.get("SPLUNK_URL", "https://localhost:8089")
SPLUNK_TOKEN = os.environ.get("SPLUNK_TOKEN")
SPLUNK_USER = os.environ.get("SPLUNK_USER")
SPLUNK_PASSWORD = os.environ.get("SPLUNK_PASSWORD")

PROVIDER = os.environ.get("LLM_PROVIDER", "ollama").lower()
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")
ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY")
ANTHROPIC_MODEL = os.environ.get("LLM_MODEL", "claude-sonnet-5-5")

SYSTEM_PROMPT = """You are an L1 SOC triage assistant working on LAB data.
Given Splunk alert results, reply in markdown with exactly these sections:
1. Summary (one sentence)
2. Likely MITRE ATT&CK technique(s) with IDs
3. Severity (Low/Medium/High) and why
4. Next investigation steps (specific log sources or SPL ideas)
5. Likely false positives
6. What you are NOT sure about
Use only the data provided. Do not invent events, fields or IP addresses."""


def load_spl(path: Path) -> str:
    """Read an .spl file, dropping '#' note lines."""
    lines = [l for l in path.read_text().splitlines() if not l.lstrip().startswith("#")]
    return "\n".join(lines).strip()


def splunk_auth():
    if SPLUNK_TOKEN:
        return {"headers": {"Authorization": f"Bearer {SPLUNK_TOKEN}"}}
    if SPLUNK_USER and SPLUNK_PASSWORD:
        return {"auth": (SPLUNK_USER, SPLUNK_PASSWORD)}
    sys.exit("Set SPLUNK_TOKEN, or SPLUNK_USER and SPLUNK_PASSWORD (or use --from-json).")


def run_search(spl: str, earliest: str):
    query = spl if spl.startswith(("search", "|")) else f"search {spl}"
    resp = requests.post(
        f"{SPLUNK_URL}/services/search/jobs/export",
        data={"search": query, "earliest_time": earliest, "output_mode": "json"},
        verify=False,
        timeout=120,
        **splunk_auth(),
    )
    resp.raise_for_status()
    rows = []
    for line in resp.text.splitlines():
        if line.strip():
            obj = json.loads(line)
            if "result" in obj:
                rows.append(obj["result"])
    return rows


def load_json_rows(path: str):
    data = json.loads(Path(path).read_text())
    if isinstance(data, dict):
        data = data.get("results", [data])
    return [r.get("result", r) if isinstance(r, dict) else r for r in data]


def redact(text: str) -> str:
    """Basic redaction before anything is sent to a model (extend as needed)."""
    return re.sub(r"[\w.+-]+@[\w-]+\.[\w.-]+", "<email>", text)


def ask_llm(payload: str) -> str:
    if PROVIDER == "ollama":
        resp = requests.post(
            f"{OLLAMA_URL}/api/chat",
            json={
                "model": OLLAMA_MODEL,
                "stream": False,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": payload},
                ],
            },
            timeout=600,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]
    if PROVIDER == "anthropic":
        if not ANTHROPIC_KEY:
            sys.exit("Set ANTHROPIC_API_KEY or use LLM_PROVIDER=ollama.")
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": ANTHROPIC_MODEL,
                "max_tokens": 900,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": payload}],
            },
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["content"][0]["text"]
    sys.exit(f"Unknown LLM_PROVIDER '{PROVIDER}'. Use 'ollama' or 'anthropic'.")


def main():
    ap = argparse.ArgumentParser(description="AI-assisted triage of a Splunk detection")
    ap.add_argument("spl_file")
    ap.add_argument("--earliest", default="-60m")
    ap.add_argument("--max-rows", type=int, default=20)
    ap.add_argument("--from-json", help="use exported Splunk results instead of querying Splunk")
    args = ap.parse_args()

    spl_path = Path(args.spl_file)
    rows = load_json_rows(args.from_json) if args.from_json else run_search(load_spl(spl_path), args.earliest)
    rows = rows[: args.max_rows]
    if not rows:
        print("No results - nothing to triage.")
        return

    raw = redact(json.dumps(rows, indent=2))
    ai_text = ask_llm(f"Detection: {spl_path.stem}\nResults (JSON):\n{raw}")

    out_dir = Path("triage_reports")
    out_dir.mkdir(exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = out_dir / f"{spl_path.stem}_{stamp}.md"
    out.write_text(
        f"# Triage report: {spl_path.stem}\n\n"
        f"Model: {PROVIDER} ({OLLAMA_MODEL if PROVIDER == 'ollama' else ANTHROPIC_MODEL})\n\n"
        f"## AI draft (UNVERIFIED)\n{ai_text}\n\n"
        f"## Raw results\n```json\n{raw}\n```\n\n"
        "## Analyst validation\n"
        "- [ ] Checked AI claims against raw logs in Splunk\n"
        "- [ ] AI mistakes / hallucinations found: \n"
        "- [ ] Final verdict (True positive / False positive / Needs escalation): \n"
    )
    print(f"Report written to {out}")


if __name__ == "__main__":
    main()
