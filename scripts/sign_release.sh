#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <artifact-dir> <gpg-key-id>" >&2
  exit 1
fi

ARTIFACT_DIR="$1"
KEY_ID="$2"

find "$ARTIFACT_DIR" -maxdepth 1 -type f ! -name '*.asc' -print0 |
while IFS= read -r -d '' artifact; do
  gpg --batch --yes --local-user "$KEY_ID" --armor --detach-sign "$artifact"
done
