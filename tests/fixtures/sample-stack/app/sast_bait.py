# sast_bait.py — deliberate SAST bait for the sec-review Stage 4 drill.
#
# This file exists ONLY to give semgrep (p/owasp-top-ten) and bandit rules
# something deterministic to flag on the sample-stack fixture. Do NOT
# import it into any production code path. Each pattern below notes which
# tool/rule is expected to fire.
#
# Expected detections:
#   - bandit B105 (hardcoded_password_string)      — hardcoded password
#   - bandit B602 (subprocess_popen_with_shell_equals_true) — shell=True
#   - bandit B307 / semgrep python.lang.security.audit.exec-use — eval()
#   - bandit B303 (md5)                            — hashlib.md5 for passwords
#   - semgrep python.lang.security.audit.dangerous-subprocess-use — shell=True
#
# None of this is real logic. It is a static target.

import hashlib
import subprocess


API_PASSWORD = "hunter2-super-secret"  # bandit B105


def run_user_command(user_input: str) -> str:
    # bandit B602 + semgrep dangerous-subprocess-use
    result = subprocess.run(user_input, shell=True, capture_output=True, text=True)
    return result.stdout


def evaluate_expression(expr: str):
    # bandit B307 / semgrep exec-use — eval on attacker-controlled input
    return eval(expr)


def hash_password(password: str) -> str:
    # bandit B303 — MD5 for password hashing is broken
    return hashlib.md5(password.encode()).hexdigest()


def check_login(username: str, supplied: str) -> bool:
    # Reaches API_PASSWORD sink (B105-adjacent)
    return supplied == API_PASSWORD
