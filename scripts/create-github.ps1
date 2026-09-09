# Creates the requested public repository; it does not upload source files.
$ErrorActionPreference = "Stop"
gh auth status
if ($LASTEXITCODE -ne 0) { throw "Run gh auth login --hostname github.com --git-protocol https --web first." }
$githubLogin = gh api user --jq .login
if ($LASTEXITCODE -ne 0 -or $githubLogin -ne "Scoston") {
    throw "Sign in to GitHub CLI as Scoston before creating the repository."
}
gh repo create "Scoston/tracebound" --public --description "AI agent authority and containment testing with verifiable evidence" --add-readme
if ($LASTEXITCODE -ne 0) { throw "Repository creation failed. Existing repositories are not changed by this script." }
gh repo view "Scoston/tracebound" --json url,isPrivate
if ($LASTEXITCODE -ne 0) { throw "Could not verify the created repository." }
