#!/bin/bash
# setup_ecc.sh - Bootstrap everything-claude-code (ECC) for Claude Code.
#
# Installs the ECC skill/agent/hook harness into ~/.claude/, idempotently
# and best-effort. Since ~/.claude is host-mounted, installs persist across
# container restarts; subsequent runs are fast no-ops.
#
# ECC repo: https://github.com/affaan-m/ECC
#
# Controls (environment variables):
#   ECC_BOOTSTRAP=0   Disable this bootstrap entirely.
#   ECC_REFRESH=1     Force re-install / update even if already set up.
#
# Always exits 0 — must never abort container startup.

set -u

export PATH="${HOME}/.local/bin:${PATH}"

LOG_PREFIX="[ecc]"
log()  { echo "${LOG_PREFIX} $*"; }
warn() { echo "${LOG_PREFIX} WARN: $*" >&2; }

case "${ECC_BOOTSTRAP:-1}" in
	0|no|NO|false|FALSE|off|OFF)
		log "ECC_BOOTSTRAP is disabled; skipping ECC setup."
		exit 0
		;;
esac

FORCE=""
case "${ECC_REFRESH:-0}" in
	1|yes|YES|true|TRUE|on|ON) FORCE="1" ;;
esac

ECC_REPO_URL="https://github.com/affaan-m/ECC"
ECC_SRC_DIR="${HOME}/.claude/.ecc-src"
SENTINEL="${HOME}/.claude/.ecc.bootstrap"

run() {
	log "+ $*"
	"$@" </dev/null || warn "command failed (ignored): $*"
}

command -v git >/dev/null 2>&1 || { warn "git not found; skipping ECC setup."; exit 0; }
command -v node >/dev/null 2>&1 || { warn "node not found; skipping ECC setup."; exit 0; }
command -v npm >/dev/null 2>&1 || { warn "npm not found; skipping ECC setup."; exit 0; }

mkdir -p "${HOME}/.claude" 2>/dev/null || true

if [ -f "${SENTINEL}" ] && [ -z "${FORCE}" ]; then
	log "ECC already installed at ${ECC_SRC_DIR} (set ECC_REFRESH=1 to update)."
	exit 0
fi

if [ ! -d "${ECC_SRC_DIR}/.git" ]; then
	log "Cloning everything-claude-code..."
	run git clone --depth 1 "${ECC_REPO_URL}" "${ECC_SRC_DIR}"
else
	log "Updating everything-claude-code..."
	run git -C "${ECC_SRC_DIR}" fetch --depth 1 origin HEAD
	run git -C "${ECC_SRC_DIR}" reset --hard FETCH_HEAD
fi

[ -d "${ECC_SRC_DIR}" ] || { warn "ECC clone/update failed; skipping install."; exit 0; }

log "Installing ECC npm dependencies..."
run npm --prefix "${ECC_SRC_DIR}" install --no-audit --no-fund --loglevel=error

log "Applying ECC to ~/.claude (target: claude, profile: core)..."
run node "${ECC_SRC_DIR}/scripts/install-apply.js" --target claude --profile core

: > "${SENTINEL}" 2>/dev/null || true
log "ECC setup complete."
exit 0
