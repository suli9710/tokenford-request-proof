#!/usr/bin/env bash
# Review this script before running. It only bootstraps this checkout's venv.
set -euo pipefail
root_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$root_dir"
python_cmd="${PROOF_PYTHON:-python3.12}"
command -v "$python_cmd" >/dev/null || { echo '需要已安装的 Python 3.12.10；可用 PROOF_PYTHON 选择程序。' >&2; exit 1; }
"$python_cmd" -c 'import sys; sys.exit(0 if sys.version_info[:3] == (3,12,10) else "此安装脚本固定使用已测 Python 3.12.10")'
for tool in node cargo ssh; do
  command -v "$tool" >/dev/null || { printf '需要先安装工具：%s\n' "$tool" >&2; exit 1; }
done
[[ "$(node --version)" == 'v24.11.1' ]] || { echo '需要 Node.js 24.11.1。' >&2; exit 1; }
if command -v rustup >/dev/null; then
  # Stop before a rustup cargo shim can auto-install a missing toolchain.
  installed_toolchains="$(rustup toolchain list)"
  has_pinned_rust=false
  while IFS= read -r toolchain_line; do
    case "$toolchain_line" in
      1.95.0|1.95.0\ *|1.95.0-*) has_pinned_rust=true ;;
    esac
  done <<< "$installed_toolchains"
  [[ "$has_pinned_rust" == true ]] || { echo '请先自行安装 Rust 1.95.0；本脚本不会安装全局工具链。' >&2; exit 1; }
fi
[[ "$(cargo --version)" == 'cargo 1.95.0 '* ]] || { echo '需要 Rust/Cargo 1.95.0。' >&2; exit 1; }
if [[ ! -e .venv ]]; then
  "$python_cmd" -m venv .venv
fi
[[ -x .venv/bin/python ]] || { echo '.venv 不是可用的 POSIX Python 环境；请使用独立目录核查。' >&2; exit 1; }
.venv/bin/python -c 'import sys; sys.exit(0 if sys.version_info[:3] == (3,12,10) else "已有 venv 不是 Python 3.12.10，请核查环境")'
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
printf '%s\n' '本地 Python 环境已准备。请先用独立认可的哈希执行 review.py check --expected-manifest，再运行 build、runtime、reproduce、audit。'
