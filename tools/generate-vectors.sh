#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
upstream=${1:-"$root/../Tally"}
expected=f8b80ee09a1ed5768f2263ff71c7c745bf946922
[ "$(git -C "$upstream" rev-parse HEAD)" = "$expected" ] || { echo 'upstream revision differs' >&2; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# CryptoKit and swift-crypto have the same SHA256 API; macOS needs no dependency build.
for src in "$upstream"/Sources/Tally/*.swift; do sed 's/^import Crypto$/import CryptoKit/' "$src" > "$tmp/$(basename "$src")"; done
swiftc -O "$tmp"/*.swift "$root/tools/GenerateVectors.swift" -o "$tmp/vectors"
"$tmp/vectors" > "$root/tests/fixtures/swift.tsv"
