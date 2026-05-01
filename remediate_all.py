import os
import sys
import csv
import argparse
import subprocess
import shutil
from datetime import datetime

def print_log(message, level="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")

def run_command(cmd, cwd=None, env=None, check=True, capture_output=False):
    """Executes a shell command and handles potential errors safely."""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            env=env,
            check=check,
            text=True,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None
        )
        return result
    except subprocess.CalledProcessError as e:
        print_log(f"Command failed: {' '.join(cmd)}", "ERROR")
        if e.stderr:
            print_log(e.stderr.strip(), "ERROR")
        raise

def validate_mailmap(filepath):
    """Ensures the mailmap file exists and follows standard Git formatting."""
    if not os.path.isfile(filepath):
        print_log(f"Mailmap file not found at: {filepath}", "ERROR")
        sys.exit(1)

    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    if not lines:
        print_log("Mailmap file is completely empty.", "ERROR")
        sys.exit(1)

    valid_entries = 0
    for line_num, line in enumerate(lines, start=1):
        line = line.strip()
        # Skip empty lines and comments
        if not line or line.startswith('#'):
            continue
        
        # Git mailmap requires emails to be wrapped in <>
        if '<' not in line or '>' not in line:
            print_log(f"Mailmap format error on line {line_num}: Missing <email> wrappers.", "ERROR")
            print_log(f"Line content: {line}", "ERROR")
            sys.exit(1)
        valid_entries += 1

    if valid_entries == 0:
        print_log("No valid mapping rules found in the mailmap.", "ERROR")
        sys.exit(1)

    print_log(f"Mailmap validated successfully ({valid_entries} rules found).")

def get_target_repos(csv_path):
    """Extracts unique repository names from the audit CSV."""
    if not os.path.isfile(csv_path):
        print_log(f"CSV file not found at: {csv_path}", "ERROR")
        sys.exit(1)

    repos = set()
    try:
        with open(csv_path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if 'Repo' in row and row['Repo'].strip():
                    repos.add(row['Repo'].strip())
    except Exception as e:
        print_log(f"Failed to parse CSV: {e}", "ERROR")
        sys.exit(1)
        
    return sorted(list(repos))

def main():
    parser = argparse.ArgumentParser(
        description="Automated Git history remediation tool using isolated Python venvs."
    )
    # Using specific flags instead of positional arguments
    parser.add_argument("-u", "--user", required=True, help="Target GitHub username (e.g., binkocd)")
    parser.add_argument("-c", "--csv", required=True, help="Path to the audit_results.csv file")
    parser.add_argument("-m", "--mailmap", required=True, help="Path to the mailmap.txt mapping file")
    parser.add_argument("-b", "--backup-dir", default="./audit_backups", help="Directory to store safety bundles")
    parser.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompts and force push automatically")

    # Display help if no arguments are passed
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    # Pre-flight validations
    validate_mailmap(args.mailmap)
    mailmap_abs_path = os.path.abspath(args.mailmap)
    repos = get_target_repos(args.csv)

    if not repos:
        print_log("No repositories found in CSV. Exiting.", "INFO")
        sys.exit(0)

    backup_dir_abs = os.path.abspath(args.backup_dir)
    os.makedirs(backup_dir_abs, exist_ok=True)

    print_log(f"Found {len(repos)} repositories to remediate.")

    for repo in repos:
        print_log("-" * 50)
        print_log(f"Target Repository: {repo}")

        work_dir = f"remediate_tmp_{repo}_{int(datetime.now().timestamp())}.git"
        
        try:
            # 1. Clone Bare Repository
            repo_url = f"https://github.com/{args.user}/{repo}.git"
            print_log(f"Cloning bare repository...")
            run_command(["git", "clone", "--bare", repo_url, work_dir])

            # Store absolute path to work_dir before we cd into it
            work_dir_abs = os.path.abspath(work_dir)
            os.chdir(work_dir_abs)

            # 2. Safety Snapshot
            bundle_name = f"{repo}_pre_rewrite_{datetime.now().strftime('%Y%m%d')}.bundle"
            bundle_path = os.path.join(backup_dir_abs, bundle_name)
            print_log(f"Creating safety bundle: {bundle_name}")
            run_command(["git", "bundle", "create", bundle_path, "--all"])

            # 3. Create and Activate Virtual Environment
            print_log("Creating isolated Python venv...")
            run_command([sys.executable, "-m", "venv", "venv"])

            # Determine platform-specific venv binary paths
            bin_dir = "Scripts" if os.name == "nt" else "bin"
            venv_pip = os.path.join("venv", bin_dir, "pip")
            venv_filter_repo = os.path.join("venv", bin_dir, "git-filter-repo")

            # Emulate activation by injecting the venv's bin directory to the front of PATH
            venv_env = os.environ.copy()
            venv_env["PATH"] = f"{os.path.abspath(os.path.join('venv', bin_dir))}{os.pathsep}{venv_env.get('PATH', '')}"

            # 4. Install git-filter-repo directly into the isolated venv
            print_log("Installing git-filter-repo inside venv...")
            run_command([venv_pip, "install", "git-filter-repo"], env=venv_env)

            # 5. Execute git-filter-repo using the venv executable
            print_log("Applying identity filters...")
            run_command([venv_filter_repo, "--mailmap", mailmap_abs_path, "--force"], env=venv_env)

            # 6. Verify Identities
            print_log("Verifying remaining identities:")
            verify_result = run_command(["git", "log", "--all", "--format=%an <%ae>"], capture_output=True)
            authors = sorted(list(set(verify_result.stdout.strip().split('\n'))))
            for author in authors:
                if author:
                    print(f"  - {author}")

            # 7. Re-link and Push
            print_log("Re-linking remote origin...")
            run_command(["git", "remote", "add", "origin", repo_url])

            if not args.yes:
                confirm = input(f"\nForce push changes for {repo} to GitHub? (y/N): ").strip().lower()
                if confirm != 'y':
                    print_log("Push aborted by user. Moving to next repository.", "WARNING")
                    # Break out of the try block to ensure we still clean up the directory
                    os.chdir("..")
                    shutil.rmtree(work_dir_abs, ignore_errors=True)
                    continue

            print_log("Force pushing history to GitHub...")
            run_command(["git", "push", "origin", "--all", "--force"])
            run_command(["git", "push", "origin", "--tags", "--force"])
            print_log(f"Successfully remediated {repo}.", "INFO")

            # 8. Deactivate/Cleanup (Return to parent directory)
            os.chdir("..")
            
        except Exception as e:
            print_log(f"Critical error processing {repo}. Check logs above. Skipping to next.", "ERROR")
            # Ensure we return to parent directory if failure happened inside work_dir
            if os.path.abspath(os.getcwd()) == work_dir_abs:
                os.chdir("..")

        finally:
            # Always clean up the temporary bare clone and the internal venv
            if os.path.exists(work_dir_abs):
                print_log(f"Cleaning up workspace: {work_dir}")
                # Use ignore_errors=True to bypass Windows read-only .git file locks during deletion
                shutil.rmtree(work_dir_abs, ignore_errors=True)

    print_log("-" * 50)
    print_log("Remediation run complete.")

if __name__ == "__main__":
    main()