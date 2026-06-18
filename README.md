# IOC Checker

A small CLI that checks IPs, domains, and file hashes against local blocklists.
The lookup decides the verdict; if Ollama is installed, a local model writes a
short triage note on top — it never changes the verdict.

## Install

```bash
pip install -r requirements.txt
ollama pull llama3.2   # optional, only for the triage note
```

## Usage

```bash
# check some indicators
python ioc_checker.py 185.220.101.45 evil-c2.example 8.8.8.8

# skip the AI note
python ioc_checker.py 185.220.101.45 --no-llm

# check a file (one IOC per line)
python ioc_checker.py -f iocs.txt
```

## Lists

Blocklists live in `lists/` as plain text — one indicator per line, optional
note after a `#`:

```
185.220.101.45    # Tor exit node
evil-c2.example   # known C2 domain
```

Files: `blocklist_ips.txt`, `blocklist_domains.txt`, `blocklist_hashes.txt`.

## Note

A "clean" result means the indicator isn't in your lists — not that it's safe.

Built with Python, click, rich, and Ollama.
