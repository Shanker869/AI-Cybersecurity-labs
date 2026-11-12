# How to push the 6 labs to GitHub (Shanker869)

## One-time setup (Windows, macOS or Linux)

1. Install Git: https://git-scm.com/downloads
2. Install GitHub CLI: https://cli.github.com
3. Sign in and set your name and email (use the email on your GitHub account):

```bash
gh auth login                      # choose GitHub.com -> HTTPS -> login with browser
git config --global user.name  "Shanker"
git config --global user.email "your-github-email@example.com"
```

## Option A: push everything with one script

Unzip `ai-security-labs.zip`, open a terminal in the unzipped folder, then run:

```bash
bash push_all.sh
```

On Windows, run it in **Git Bash** (installed with Git). The script creates each public repo,
makes the first commit under **your** name and pushes it. It also creates the `Shanker869/Shanker869`
profile README repo, which shows on your GitHub profile page.

## Option B: one repo at a time (manual)

```bash
cd ai-windows-auth-log-analyzer
git init -b main
git add .
git commit -m "Initial commit: AI Windows authentication log analyzer"
gh repo create Shanker869/ai-windows-auth-log-analyzer --public --source=. --push \
  --description "AI-assisted Windows authentication log analyzer with MITRE ATT&CK mapping"
```

Repeat for the other folders.

## After pushing

- Open each repo and check that the **Actions** tab shows a green ✓ (tests ran).
- Pin the 6 repos on your profile: Profile → *Customize your pins*.
- Add topics to each repo (gear icon next to *About*): `cybersecurity`, `soc`, `mitre-attack`, `python`, `llm`, `home-lab`.
- Better than one big commit: make a few small commits as you try each lab yourself (run it on
  your own VM logs, tweak a rule, add a test). Interviewers look at commit history.

## Before interviews: run each lab yourself

```bash
cd ai-soc-alert-triage
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt pytest
pytest -q
```

Then follow the *Quick start* in each README. Be ready to explain every detection rule and every
scoring choice. Only put numbers on your resume that you measured yourself.
