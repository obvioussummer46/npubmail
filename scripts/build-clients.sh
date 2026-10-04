#!/usr/bin/env bash
# Build release binaries of the clients into dist/ (served at /dl/ by npubmaild -downloads).
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf dist && mkdir -p dist
for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do
  os=${t%/*}; arch=${t#*/}; ext=""; [ "$os" = windows ] && ext=.exe
  for b in npubmail npubmail-mcp; do
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags="-s -w" -o "dist/$b-$os-$arch$ext" "./cmd/$b"
  done
done
(cd dist && sha256sum -- * > SHA256SUMS)
ls dist
