# Intentionally insecure Python — fixture for python-runner / ruff + pip-audit.
# Carries multiple Sxxx and Bxxx findings:
#   S102 (exec), S301 (pickle.loads), S307 (eval), S324 (md5),
#   S501 (verify=False), S506 (yaml.load without SafeLoader),
#   S605 (subprocess shell=True), S105 (hardcoded password),
#   S311 (random for token), B902 (probably).

import hashlib
import pickle
import random
import string
import subprocess

import requests
import yaml

API_KEY = "sk_live_4242424242424242"
DB_PASSWORD = "hunter2"


def restore_state(payload):
    return pickle.loads(payload)


def render(template, ctx):
    return eval(template.format(**ctx))


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()


def session_token():
    return "".join(random.choices(string.ascii_letters + string.digits, k=32))


def fetch(url):
    return requests.get(url, verify=False).text


def load_config(yaml_text):
    return yaml.load(yaml_text)


def shell_exec(cmd):
    subprocess.run(f"echo {cmd}", shell=True)


def dynamic_call(code):
    exec(code)
