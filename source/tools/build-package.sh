#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 LUDUS_ROOT OUTPUT_DIRECTORY" >&2
    exit 2
fi

plugin_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ludus_root=$(CDPATH= cd -- "$1" && pwd)
mkdir -p "$2"
output_dir=$(CDPATH= cd -- "$2" && pwd)

if [ ! -f "$ludus_root/ludus-api/pluginrpc/plugin.go" ]; then
    echo "Ludus checkout does not contain the RPC plugin SDK: $ludus_root" >&2
    exit 1
fi

temporary=$(mktemp -d "${TMPDIR:-/var/tmp}/ludus-console-wall.XXXXXX")
cleanup() { chmod -R u+w "$temporary" 2>/dev/null || true; rm -rf "$temporary"; }
trap cleanup EXIT HUP INT TERM

cat >"$temporary/go.work" <<EOF
go 1.25.0
use (
  $plugin_root
  $ludus_root/ludus-api
  $ludus_root/ludus-server
  $ludus_root/ludus-client
  $ludus_root/dynamic-inventory
)
EOF

cd "$plugin_root"
GOWORK="$temporary/go.work" GOFLAGS=-mod=readonly go test ./...
GOWORK="$temporary/go.work" GOFLAGS=-mod=readonly go test -race ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOWORK="$temporary/go.work" GOFLAGS=-mod=readonly \
    go build -buildvcs=false -trimpath -ldflags "-s -w" -o "$temporary/plugin" .
chmod 0555 "$temporary/plugin"
mkdir "$temporary/ui"
cp ui/index.html "$temporary/ui/index.html"
cat >"$temporary/plugin.json" <<'EOF'
{"schemaVersion":1,"id":"console-wall-v120","name":"Ludus Console Wall","version":"1.2.0","description":"A multi-range VM console wall with interactive Proxmox VNC and KasmVNC sessions.","author":"Ludus","executable":"plugin","protocolVersion":2,"ui":"ui/index.html","rangeScoped":false}
EOF

package="$output_dir/ludus-console-wall-1.2.0.zip"
(cd "$temporary" && zip -q -X "$package" plugin.json plugin ui/index.html)
(cd "$output_dir" && sha256sum "$(basename -- "$package")" >"$(basename -- "$package").sha256")
echo "$package"
