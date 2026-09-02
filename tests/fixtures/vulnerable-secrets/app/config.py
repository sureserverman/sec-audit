import os

# Fixture secret — FAKE hardcoded token for the secrets lane. See ../README.md.
DEBUG = True

# Anti-pattern: hardcoded API token that should come from os.environ.
api_token = "tok_live_9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a"


def client_headers():
    return {"Authorization": f"Bearer {api_token}"}
