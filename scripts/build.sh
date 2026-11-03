#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --release -p hisame-driver
cargo build --release -p hisame-harness --target riscv64gc-unknown-none-elf
