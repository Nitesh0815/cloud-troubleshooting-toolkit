# toolkit.py - Wrapper to run all my AWS troubleshooting scripts

import subprocess
import os
import sys
import io

# ---- Basic Config ----
# Update this with your actual instance details
TEST_INSTANCE_ID = "i-0a88b4214c12dcf0a"
TEST_PROTOCOL = "tcp"
TEST_PORT = "22"

# Force stdout/stderr to use UTF-8 so Windows doesn't choke on weird characters
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")


def run_script(script_path, output_file, args=None):
    """
    Small helper to run a python script, grab the output,
    save it inside 'reports/', and show a short summary.
    """
    if args is None:
        args = []

    # Make sure I'm not trying to run some missing file
    if not os.path.exists(script_path):
        print(f"❌ Script not found: {script_path}")
        return

    cmd = [sys.executable, script_path] + args

    try:
        # reports folder (if user deleted it, create again)
        os.makedirs("reports", exist_ok=True)

        print(f"\n>>> Running {script_path} ...")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            encoding="utf-8",
            errors="replace"
        )

        # Write full output to file
        out_path = os.path.join("reports", output_file)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(result.stdout)

        print(f"  ✔ Output saved to {out_path}")
        print("  Summary:")

        lines = result.stdout.splitlines()

        # Cost checker has a special ending line
        if "TOTAL ESTIMATED MONTHLY SAVINGS" in result.stdout:
            print("   " + lines[-2])
        else:
            # Just display a few lines from the bottom
            for l in lines[-6:]:
                if l.strip() and not l.startswith("---"):
                    print("   " + l)

    except subprocess.CalledProcessError as e:
        print(f"  ❌ Script failed (exit code {e.returncode})")
        print(f"  Cmd: {' '.join(cmd)}")
        if e.stderr:
            print("  Stderr:", e.stderr.strip())
        print("  (Probably AWS credentials/permissions issue)")

    except Exception as e:
        print(f"  ❌ Unexpected error: {e}")


if __name__ == "__main__":

    print("\n====================================================")
    print("   Cloud Infra Troubleshooting Toolkit (My Wrapper)  ")
    print("====================================================")

    # 1. EC2 connectivity test
    run_script(
        "Connectivity_Checker.py",
        "connectivity_report.txt",
        args=[
            "--instance-id", TEST_INSTANCE_ID,
            "--protocol", TEST_PROTOCOL,
            "--port", str(TEST_PORT)
        ]
    )

    print("\n" + "-" * 60)

    # 2. S3 permissions check
    run_script("S3_Auditor.py", "s3_audit_report.txt")

    print("\n" + "-" * 60)

    # 3. IAM analyzer
    run_script("IAM_Analyzer.py", "iam_audit_report.txt")

    print("\n" + "-" * 60)

    # 4. Cost optimization scan
    run_script("Cost_Checker.py", "cost_optimization_report.txt")

    print("\n====================================================")
    print("   All tasks completed. Check the reports folder.    ")
    print("====================================================\n")
