# Publish TraceBound to GitHub

The requested destination is a new **public** repository named
`Scoston/tracebound`. These commands assume GitHub CLI (`gh`) is already installed.

## Create the repository for the connected upload

In PowerShell:

```powershell
gh auth status
$githubLogin = gh api user --jq .login
if ($githubLogin -ne "Scoston") { throw "Sign in to GitHub CLI as Scoston before continuing." }

gh repo create "Scoston/tracebound" `
  --public `
  --description "AI agent authority and containment testing with verifiable evidence" `
  --add-readme

gh repo view "Scoston/tracebound" --json url,isPrivate
```

The expected visibility result is `"isPrivate": false`. Return the displayed
repository URL so the already prepared source can be uploaded through the
connected GitHub account. If the connection uses selected repositories, include
the new repository in that connection's permitted repository list.

If `gh auth status` reports no login, run `gh auth login --hostname github.com
--git-protocol https --web` first. Never paste a token into a conversation.

## Optional: upload the downloaded package yourself

After creating the repository, extract `TraceBound-v0.1.0.zip`. Keep that source
directory separate from a fresh clone. The clone preserves GitHub's initial
commit; these commands do not force-push.

```powershell
$sourcePath = (Resolve-Path ".\TraceBound-v0.1.0\tracebound").Path
gh repo clone "Scoston/tracebound" ".\tracebound-publish"
if ($LASTEXITCODE -ne 0) { throw "Clone failed." }

Get-ChildItem -LiteralPath $sourcePath -Force |
  Where-Object { $_.Name -notin @(".git", ".venv", "__pycache__", "output", "state", "build", "dist") } |
  Copy-Item -Destination ".\tracebound-publish" -Recurse -Force

Set-Location ".\tracebound-publish"
git add --all
git diff --cached --stat
git commit -m "Add TraceBound v0.1.0 containment research lab"
if ($LASTEXITCODE -ne 0) { throw "Commit failed." }
git push origin HEAD
if ($LASTEXITCODE -ne 0) { throw "Push failed." }
gh repo view "Scoston/tracebound" --web
```

Use the pristine downloaded source for this optional path. Do not copy a working
directory containing live evidence or secrets. The package includes only source,
documentation, tests and synthetic examples. Inspect the staged file list before
committing. Enable private vulnerability reporting in the repository's security
settings after publication.
