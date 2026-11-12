#!/bin/sh
# Rebuilds vendor/noble.js from the exact noble versions (docs/10 §2.1, ADR 0021). Only what the SDK uses, tree-shaken,
# not minified (readable). Check the result against SUMS - a new version needs a new review and a new SUMS line.
set -e
DIR=$(mktemp -d)
cd "$DIR"
npm init -y >/dev/null
npm install --ignore-scripts @noble/curves@2.4.0 @noble/hashes@2.4.0 @noble/ciphers@2.4.0 esbuild@0.25.12 >/dev/null
cat > entry.js <<'JS'
export { ed25519, x25519 } from '@noble/curves/ed25519.js';
export { sha256, sha512 } from '@noble/hashes/sha2.js';
export { hkdf } from '@noble/hashes/hkdf.js';
export { chacha20poly1305 } from '@noble/ciphers/chacha.js';
JS
node node_modules/esbuild/bin/esbuild entry.js --bundle --format=esm --platform=neutral --tree-shaking=true \
  --legal-comments=inline --outfile=noble.js
sha256sum noble.js
echo "Ergebnis: $DIR/noble.js"
