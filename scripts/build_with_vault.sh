#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

set -e

function cleanup {
  echo ""
  echo "==> Cleaning up"
  kill -INT "$VAULT_PID"
  rm -rf "$SCRATCH"
}
trap cleanup EXIT SIGINT

MNT_PATH="couchbase"
PLUGIN_NAME="vault-plugin-database-couchbase"
PLUGIN_CATALOG_NAME="couchbase"

#
# Helper script for local development. Automatically builds and registers the
# plugin. Requires `vault` is installed and available on $PATH.
#

# Get the right dir
DIR="$(cd "$(dirname "$(readlink "$0")")" && pwd)"

echo "==> Starting dev"

echo "--> Scratch dir"
echo "    Creating"
SCRATCH="$DIR/tmp"
mkdir -p "$SCRATCH/plugins"

echo "--> Vault server"
echo "    Writing config"
tee "$SCRATCH/vault.hcl" > /dev/null <<EOF
plugin_directory = "$SCRATCH/plugins"
EOF

echo "    Envvars"
export VAULT_DEV_ROOT_TOKEN_ID="root"
export VAULT_ADDR="http://127.0.0.1:8200"

if vault status >/dev/null 2>&1; then echo "     ERROR: Vault is already running."; exit 1; fi

echo "    Starting"
vault server \
  -dev \
  -log-level="debug" \
  -config="$SCRATCH/vault.hcl" \
  -dev-ha -dev-transactional -dev-root-token-id=root \
  &
sleep 2
VAULT_PID=$!

echo "    Authing"
vault login root &>/dev/null

echo "--> Building"
go build -o "$SCRATCH/plugins/$PLUGIN_NAME" "./cmd/vault-plugin-database-couchbase"
SHASUM=$(shasum -a 256 "$SCRATCH/plugins/$PLUGIN_NAME" | cut -d " " -f1)

echo "    Registering plugin"
vault write sys/plugins/catalog/$PLUGIN_CATALOG_NAME \
  sha_256="$SHASUM" \
  command="$PLUGIN_NAME"

echo "    Mounting plugin"
vault secrets enable database

if [ -e scripts/custom.sh ]
then
  . scripts/custom.sh
fi

echo "==> Ready!"
wait $!
