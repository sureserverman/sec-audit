import os

# Fixture secret — FAKE hardcoded token for the secrets lane. See ../README.md.
DEBUG = True

# Anti-pattern: hardcoded API token that should come from os.environ.
api_token = "tok_live_FAKE1234567890abcdefFAKE0987654321zz"


def client_headers():
    return {"Authorization": f"Bearer {api_token}"}
