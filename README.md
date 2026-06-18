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

## Ollama triage note (optional)

If [Ollama](https://ollama.com) is installed and running, the tool adds a short
AI-written triage note under the results. It's purely descriptive — it never
changes a verdict. The tool works fine without it.

```bash
# 1. install Ollama, then start the service (usually runs automatically)
ollama serve

# 2. pull a model (default is llama3.2)
ollama pull llama3.2

# 3. install the python client so the tool can talk to Ollama
pip install ollama

# 4. just run normally — the triage note appears automatically
python ioc_checker.py 185.220.101.45 evil-c2.example

# use a different model
python ioc_checker.py 185.220.101.45 --model mistral

# turn the note off for any run
python ioc_checker.py 185.220.101.45 --no-llm
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
