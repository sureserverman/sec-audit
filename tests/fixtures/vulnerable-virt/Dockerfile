# Intentionally insecure Dockerfile — fixture for virt-runner / hadolint.
# Six DLxxxx + shellcheck findings expected: DL3007 (latest tag),
# DL3002 (USER root), DL3008 (apt-get without version pin),
# DL3009 (apt-get without rm -rf /var/lib/apt/lists), DL4006 (no pipefail),
# SC2086 (unquoted $VAR in shell).

FROM python:latest

USER root

ENV TARGET_DIR=/srv/app

RUN apt-get update && apt-get install -y curl
RUN curl https://example.com/install.sh | bash

WORKDIR $TARGET_DIR
COPY . .

CMD echo $TARGET_DIR && python app.py
