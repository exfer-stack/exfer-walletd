#!/bin/sh
# Deploy to fly.io. The build context is this repository only — the
# `exfer` dependency is pulled from GitHub at cargo-build time, so no
# parent-directory contortions are needed.

set -eu
cd "$(dirname "$0")/.."
exec fly deploy --remote-only --ha=false "$@"
