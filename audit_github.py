import os
import sys
import csv
import argparse
import subprocess
import tempfile
from datetime import datetime
from github import Github, Auth
from github.GithubException import GithubException
from github.GithubRetry import GithubRetry

# --- Dynamic Configuration ---
# Pulled from environment variables (GitHub Actions vars or local exports)
AUTHORIZED_NAME = os.environ.get("AUTHORIZED_NAME", "").strip()

# Parse comma-separated lists into clean, lowercase arrays
unauth_names_raw = os.environ.get("UNAUTHORIZED_NAMES", "")
UNAUTHORIZED_NAMES = [name.strip().lower() for name in unauth_names_raw.split(',')] if unauth_names_raw else []

unauth_emails_raw = os.environ.get("UNAUTHORIZED_EMAILS", "")
UNAUTHORIZED_EMAILS = [email.strip().lower() for email in unauth_emails_raw.split(',')] if unauth_emails_raw else []

def is_violation(author_name, author_email):
    name_lower = author_name.lower().strip()
    email_lower = author_email.lower().strip()

    # Dynamic check for GitHub noreply format based on the authorized name
    is_valid_github_email = False
    if AUTHORIZED_NAME:
        is_valid_github_email = email_lower.endswith("@users.noreply.github.com") and AUTHORIZED_NAME.lower() in email_lower

    # Rule 1: Flag explicitly unauthorized names
    if name_lower in UNAUTHORIZED_NAMES:
        return True
    
    # Rule 2: Flag explicitly unauthorized emails
    if email_lower in UNAUTHORIZED_EMAILS:
        return True
    
    # Rule 3: Flag if name matches authorized name, but email is NOT a valid GitHub noreply
    if AUTHORIZED_NAME and name_lower == AUTHORIZED_NAME.lower() and not is_valid_github_email:
        return True
        
    return False

# --- Git Operations ---
def run_git_command(args, cwd):
    try:
        result = subprocess.run(
            ["git"] + args,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Git command failed: {e.stderr}", file=sys.stderr)
        return ""

def audit_repo(repo_name, repo_dir, since_date=None):
    violations = []
    seen_hashes = set()
    
    log_args = ["log", "--all", "--format=%H|%aI|%an|%ae|%D"]
    if since_date:
        log_args.append(f"--since={since_date}")
        
    log_output = run_git_command(log_args, cwd=repo_dir)
    if not log_output:
        return violations

    for line in log_output.split('\n'):
        if not line.strip():
            continue
            
        parts = line.split('|', 4)
        if len(parts) < 4:
            continue
            
        commit_hash, date, name, email = parts[0], parts[1], parts[2], parts[3]
        refs = parts[4] if len(parts) == 5 else ""
        branch = refs.split(',')[0].strip() if refs else "detached/unknown"
        
        if commit_hash not in seen_hashes:
            seen_hashes.add(commit_hash)
            if is_violation(name, email):
                violations.append({
                    "Repo": repo_name,
                    "Branch": branch.replace('HEAD -> ', ''),
                    "Commit Hash": commit_hash,
                    "Date": date,
                    "Author Name": name,
                    "Author Email": email
                })
                
    return violations

# --- GitHub Issue Reporting ---
def report_to_github(g, home_repo_name, violations):
    print(f"Locating home repo: {home_repo_name}...")
    try:
        repo = g.get_repo(home_repo_name)
    except GithubException as e:
        print(f"Could not find HOME_REPO ({home_repo_name}): {e}")
        return

    issue_title = "[SECURITY-AUDIT] Account Leak Report"
    
    if not violations:
        body = "✅ **Audit Complete:** No identity leaks found in the authorized repositories."
    else:
        body = "⚠️ **Identity Leaks Detected!**\n\nThe following commits violate the authorized identity constraints:\n\n"
        body += "| Repo | Commit | Date | Author Name | Author Email |\n"
        body += "|------|--------|------|-------------|--------------|\n"
        for v in violations:
            short_hash = v["Commit Hash"][:7]
            body += f"| {v['Repo']} | `{short_hash}` | {v['Date'][:10]} | {v['Author Name']} | {v['Author Email']} |\n"

    open_issues = repo.get_issues(state='open')
    existing_issue = next((issue for issue in open_issues if issue.title == issue_title), None)

    if existing_issue:
        print(f"Updating existing issue #{existing_issue.number}...")
        existing_issue.edit(body=body)
    else:
        print("Creating new security audit issue...")
        try:
            repo.create_issue(title=issue_title, body=body, labels=["security"])
        except GithubException as e:
            repo.create_issue(title=issue_title, body=body)

# --- Main Execution ---
def main():
    parser = argparse.ArgumentParser(description="Audit Git history for identity leaks.")
    parser.add_argument("--local", action="store_true", help="Run in the current local directory only.")
    args = parser.parse_args()

    # Pre-flight check for identity config
    if not AUTHORIZED_NAME and not UNAUTHORIZED_NAMES and not UNAUTHORIZED_EMAILS:
        print("Warning: No identity rules configured. Set AUTHORIZED_NAME, UNAUTHORIZED_NAMES, or UNAUTHORIZED_EMAILS environment variables.", file=sys.stderr)

    all_violations = []

    if args.local:
        print(f"Running in local mode on directory: {os.getcwd()}")
        repo_name = os.path.basename(os.getcwd())
        all_violations = audit_repo(repo_name, os.getcwd())
    else:
        token = os.environ.get("GH_PAT")
        home_repo = os.environ.get("HOME_REPO")
        
        if not token or not home_repo:
            print("Error: GH_PAT and HOME_REPO environment variables are required for remote execution.")
            sys.exit(1)

        retry = GithubRetry(total=5, backoff_factor=2)
        auth = Auth.Token(token)
        g = Github(auth=auth, retry=retry)
        
        user = g.get_user()
        print(f"Authenticated as: {user.login}")

        repos = user.get_repos(type="owner")
        
        for repo in repos:
            # SKIP: Organizations and Archived repositories
            if repo.organization or repo.archived:
                status = "Archived" if repo.archived else "Org"
                print(f"Skipping: {repo.full_name} ({status})")
                continue
                
            print(f"Auditing: {repo.full_name} {'(Fork)' if repo.fork else ''}")
            
            with tempfile.TemporaryDirectory() as tmp_dir:
                clone_url = repo.clone_url.replace("https://", f"https://oauth2:{token}@")
                
                print(f"  Cloning mirror to memory/tmp...")
                run_git_command(["clone", "--mirror", clone_url, tmp_dir], cwd=os.getcwd())
                
                since_date = repo.created_at.isoformat() + "Z" if repo.fork else None
                violations = audit_repo(repo.name, tmp_dir, since_date)
                
                if violations:
                    print(f"  Found {len(violations)} violations.")
                    all_violations.extend(violations)

        report_to_github(g, home_repo, all_violations)

    csv_file = "audit_results.csv"
    with open(csv_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=["Repo", "Branch", "Commit Hash", "Date", "Author Name", "Author Email"])
        writer.writeheader()
        writer.writerows(all_violations)
        
    print(f"\nAudit complete. Found {len(all_violations)} violations. Details exported to {csv_file}")

if __name__ == "__main__":
    main()