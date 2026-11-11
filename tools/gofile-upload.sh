#!/bin/bash
# Upload one explicitly selected CI artifact. Never print GoFile guest tokens.
set -euo pipefail

if [[ $# != 1 || ! -f "$1" || ! -r "$1" || ! -s "$1" ]]; then
    echo 'ERROR: Specify one readable, nonempty file.' >&2
    exit 1
fi
upload_file="$1"
upload_name=$(basename -- "$upload_file")
if [[ "$upload_file" == *$'\n'* || "$upload_file" == *$'\r'* ]]; then
    echo 'ERROR: Newlines in filenames are unsupported.' >&2
    exit 1
fi

# Keep the payload unchanged; only these temporary API responses are removed.
response_dir=$(mktemp -d)
trap 'rm -rf -- "$response_dir"' EXIT
curl --fail --silent --show-error --proto '=https' \
    --connect-timeout 20 --max-time 60 --retry 2 --max-filesize 1048576 \
    https://api.gofile.io/servers > "$response_dir/servers.json"
server=$(jq -er '
    select(.status == "ok") | .data.servers[0].name |
    select(type == "string" and test("^[A-Za-z0-9][A-Za-z0-9-]{0,62}$"))
' "$response_dir/servers.json")

# curl's multipart parser also interprets quotes/backslashes, not only the shell.
form_file=${upload_file//\\/\\\\}
form_file=${form_file//\"/\\\"}
curl --fail --silent --show-error --proto '=https' \
    --connect-timeout 20 --max-time 1800 --max-filesize 1048576 \
    --form "file=@\"${form_file}\"" \
    "https://${server}.gofile.io/uploadFile" > "$response_dir/upload.json"
link=$(jq -er '
    select(.status == "ok") | .data.downloadPage |
    select(type == "string" and test("^https://gofile[.]io/d/[A-Za-z0-9_-]+$"))
' "$response_dir/upload.json")
digest=$(python3 - "$upload_file" <<'PY'
import hashlib, sys
with open(sys.argv[1], 'rb') as artifact:
    digest = hashlib.sha256()
    for block in iter(lambda: artifact.read(1024 * 1024), b''):
        digest.update(block)
print(digest.hexdigest())
PY
)

printf '%s\n' "$link"
printf 'SHA256: %s  %s\n' "$digest" "$upload_name"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf 'url=%s\nsha256=%s\n' "$link" "$digest" >> "$GITHUB_OUTPUT"
fi
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
        printf '\n### GoFile fallback: %s\n\n' "$upload_name"
        printf 'Download: %s\n\n' "$link"
        printf 'SHA256: `%s`\n\n' "$digest"
        printf 'Commit: `%s` · Run: `%s` · Attempt: `%s`\n' \
            "${GITHUB_SHA:-unknown}" "${GITHUB_RUN_ID:-unknown}" "${GITHUB_RUN_ATTEMPT:-unknown}"
    } >> "$GITHUB_STEP_SUMMARY"
fi
