"""
ioc_checker.py

Quick CLI to check IPs / domains / file hashes against blocklists I keep
in lists/. The lookup is what decides clean-vs-malicious; if Ollama is
around it'll write a little triage note on top, but that's just flavour -
it never gets a vote on the verdict.
"""

import re
import sys
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

__version__ = "1.0.0"
DEFANGED_DOT_RE = re.compile(r"\s*(?:\[\s*dot\s*\]|\(\s*dot\s*\)|\[\.\]|\(\.\)|\bdot\b)\s*")


def banner() -> str:
    """ASCII banner via pyfiglet, with a plain fallback if not installed."""
    try:
        import pyfiglet
        return pyfiglet.figlet_format("IOC Checker", font="slant")
    except Exception:
        return "IOC Checker"


def refang(indicator):
    s = indicator.strip().lower()
    s = s.replace("hxxps", "https").replace("hxxp", "http").replace("[:]", ":")
    return DEFANGED_DOT_RE.sub(".", s)


# md5 / sha1 / sha256 -> 32, 40 or 64 hex chars
HASH_RE = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$")
# domain regex - the lookahead caps total length at 253. took me a while
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+$")


def is_valid_ipv4(s):
    parts = s.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        # isdigit() also keeps out negatives and "" so int() is safe here
        if not p.isdigit() or int(p) > 255:
            return False
    return True


def normalize(indicator):
    """clean up the raw input and figure out what kind of IOC it is."""
    ind = refang(indicator)
    # strip scheme + any path/query so a pasted URL collapses to the host
    ind = re.sub(r"^https?://", "", ind)
    ind = ind.split("/")[0].split("?")[0].strip()
    # note: doesn't strip a :port yet, hasn't bitten me but worth knowing

    if HASH_RE.match(ind):
        return ind, "hash"
    if is_valid_ipv4(ind):
        return ind, "ip"
    if DOMAIN_RE.match(ind):
        return ind, "domain"
    return ind, "unknown"


# filename for each list type. add more here if the lists ever grow.
LIST_FILES = {
    "ip": "blocklist_ips.txt",
    "domain": "blocklist_domains.txt",
    "hash": "blocklist_hashes.txt",
}


def load_lists(lists_dir):
    # db looks like {"ip": {indicator: note, ...}, "domain": {...}, ...}
    db = {"ip": {}, "domain": {}, "hash": {}}
    base = Path(lists_dir)

    for ioc_type, filename in LIST_FILES.items():
        path = base / filename
        if not path.exists():
            # missing list is fine - just means we can't match that type
            continue

        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # lines can be "indicator  # optional note about why it's bad"
            if "#" in line:
                indicator, note = line.split("#", 1)
                indicator, note = indicator.strip(), note.strip()
            else:
                indicator, note = line, ""

            db[ioc_type][indicator.lower()] = note

    return db


def check(indicator, db):
    ind, ioc_type = normalize(indicator)
    result = {
        "input": indicator,
        "indicator": ind,
        "type": ioc_type,
        "verdict": "unknown",
        "note": "",
    }

    if ioc_type == "unknown":
        result["note"] = "Could not classify as IP, domain, or hash."
        return result

    hits = db.get(ioc_type, {})
    if ind in hits:
        result["verdict"] = "malicious"
        result["note"] = hits[ind] or "Matched local blocklist."
    else:
        result["verdict"] = "clean"
        result["note"] = "No match in local lists."

    return result


def narrate(results, model="llama3.2"):
    """
    Ask local Ollama to summarise the run as a triage note.
    Returns None if ollama isn't installed - tool works fine without it.
    """
    try:
        import ollama
    except ImportError:
        return None

    lines = []
    for r in results:
        line = f"- {r['indicator']} ({r['type']}): {r['verdict']}"
        if r["note"]:
            line += f" - {r['note']}"
        lines.append(line)
    summary = "\n".join(lines)

    prompt = (
        "You are a SOC analyst assistant. Below are IOC lookup results from a "
        "local threat-intel list. The verdicts are already decided - do NOT "
        "change them. Write a short (3-5 sentence) triage note: what was found, "
        "the likely risk, and one recommended next action. Be concise and factual.\n\n"
        f"Results:\n{summary}"
    )

    try:
        resp = ollama.chat(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.2},
        )
        return resp["message"]["content"].strip()
    except Exception as e:
        # don't blow up the whole run just because the model hiccuped
        return f"(LLM narration unavailable: {e})"


VERDICT_STYLE = {"malicious": "bold red", "clean": "green", "unknown": "yellow"}


@click.command()
@click.argument("indicators", nargs=-1)
@click.option("--file", "-f", "file", type=click.Path(exists=True),
              help="File with one IOC per line.")
@click.option("--lists-dir", default="lists", show_default=True,
              help="Directory holding the blocklist files.")
@click.option("--model", default="llama3.2", show_default=True,
              help="Ollama model for the triage note.")
@click.option("--no-llm", is_flag=True, help="Skip the Ollama narration.")
def main(indicators, file, lists_dir, model, no_llm):
    """Check IPs, domains, or hashes against local threat-intel lists."""
    iocs = list(indicators)

    if file:
        with open(file) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    iocs.append(line)

    if not iocs:
        console.print("[yellow]No indicators given. Pass args or use --file.[/]")
        sys.exit(1)

    db = load_lists(lists_dir)
    results = [check(i, db) for i in iocs]

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header = (
        f"[bold cyan]{banner()}[/]"
        f"[dim]v{__version__}  |  Scanning {len(iocs)} indicator(s)  |  {timestamp}[/]"
    )
    console.print(Panel(header, border_style="cyan", expand=False))

    table = Table(title="IOC Check Results")
    table.add_column("Indicator", overflow="fold")
    table.add_column("Type")
    table.add_column("Verdict")
    table.add_column("Note", overflow="fold")
    for r in results:
        style = VERDICT_STYLE.get(r["verdict"], "white")
        verdict = f"[{style}]{r['verdict'].upper()}[/]"
        table.add_row(r["indicator"], r["type"], verdict, r["note"])
    console.print(table)

    if not no_llm:
        note = narrate(results, model=model)
        if note:
            console.print(Panel(note, title="Triage Note (Ollama)", border_style="cyan"))


if __name__ == "__main__":
    main()
