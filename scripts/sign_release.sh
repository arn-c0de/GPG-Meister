#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <artifact-dir> <gpg-key-id>" >&2
  exit 1
fi

ARTIFACT_DIR="$1"
KEY_ID="$2"

mapfile -d '' ARTIFACTS < <(find "$ARTIFACT_DIR" -maxdepth 1 -type f ! -name '*.asc' ! -name 'SHA256SUMS' -print0 | sort -z)

if [ "${#ARTIFACTS[@]}" -eq 0 ]; then
  echo "no artifacts found in $ARTIFACT_DIR" >&2
  exit 1
fi

(
  cd "$ARTIFACT_DIR"
  : > SHA256SUMS
  for artifact in "${ARTIFACTS[@]}"; do
    sha256sum "$(basename "$artifact")" >> SHA256SUMS
  done
)

gpg --batch --yes --local-user "$KEY_ID" --armor --detach-sign "$ARTIFACT_DIR/SHA256SUMS"

for artifact in "${ARTIFACTS[@]}"; do
  gpg --batch --yes --local-user "$KEY_ID" --armor --detach-sign "$artifact"
done

gpg --batch --verify "$ARTIFACT_DIR/SHA256SUMS.asc" "$ARTIFACT_DIR/SHA256SUMS"
