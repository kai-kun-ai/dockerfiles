#!/bin/bash
set -eu

if [ "$#" -eq 0 ]; then
	set -- /bin/bash
fi

function update_startup_tools() {
	command -v npm > /dev/null || {
		echo "ERROR: npm not found; cannot update codex" >&2
		exit 1
	}
	echo "Updating codex..."
	npm install -g @openai/codex@latest
	hash -r

	echo "Updating claude..."
	sudo -iu "${LOCAL_WHOAMI}" bash -c "curl -fsSL https://claude.ai/install.sh | bash"
	for profile in /home/${LOCAL_WHOAMI}/.bashrc /home/${LOCAL_WHOAMI}/.profile; do
		grep -qxF 'export PATH="${HOME}/.local/bin:$PATH"' "${profile}" || \
			echo 'export PATH="${HOME}/.local/bin:$PATH"' >> "${profile}"
	done

	echo "Setting up standard skills (claude/codex plugins)..."
	sudo -iu "${LOCAL_WHOAMI}" env \
		HOME="/home/${LOCAL_WHOAMI}" \
		SKILLS_BOOTSTRAP="${SKILLS_BOOTSTRAP:-}" \
		SKILLS_REFRESH="${SKILLS_REFRESH:-}" \
		bash /usr/local/bin/setup_skills.sh || true
}

function setup_exec_audit() {
	# OS-level exec auditing via snoopy (issue #280). snoopy is enabled
	# image-wide through /etc/ld.so.preload, so it records every execve() that
	# happens in the container regardless of what the agents log themselves.
	# Here we only prepare the (host-mounted) log location and honour an opt-out.
	case "${EXEC_AUDIT:-1}" in
		0|no|NO|false|FALSE|off|OFF)
			# Disable snoopy for this container run by emptying the preload list.
			: > /etc/ld.so.preload 2>/dev/null || true
			echo "[audit] EXEC_AUDIT disabled: snoopy exec auditing is off for this run."
			return 0
			;;
	esac
	# /var/log/ai-audit is bind-mounted from the host (~/.shared_cache.ai-audit)
	# when launched via the Makefile, so the log survives the --rm container.
	mkdir -p /var/log/ai-audit 2>/dev/null || true
	touch /var/log/ai-audit/exec.log 2>/dev/null || true
	# Both the work user and root (via sudo) must be able to append so the
	# OS-level record stays complete in this single-user container.
	chmod 0666 /var/log/ai-audit/exec.log 2>/dev/null || true
	echo "[audit] snoopy exec auditing on -> /var/log/ai-audit/exec.log (EXEC_AUDIT=0 to disable; run 'ai-audit' for a report)."
}

function exec_usershell() {
	cd "${WORK_DIR}"
	exec sudo -H -u "${LOCAL_WHOAMI}" env \
		HOME="/home/${LOCAL_WHOAMI}" \
		USER="${LOCAL_WHOAMI}" \
		LOGNAME="${LOCAL_WHOAMI}" \
		PATH="/home/${LOCAL_WHOAMI}/.local/bin:${PATH}" \
		bash -c 'cd "$1" || exit 1; shift; exec "$@"' bash "${WORK_DIR}" "$@"
}

function notice_codex_setup() {
	# Show a reminder to finish wiring cc-plugin-codex inside Codex.
	# Only relevant when launching Codex, only while the one-time step is pending.
	local cmd="${1:-}"
	if [ "${cmd}" != "codex" ]; then
		return 0
	fi

	local codex_home="/home/${LOCAL_WHOAMI}/.codex"
	if [ ! -f "${codex_home}/.cc-plugin-codex.bootstrap" ]; then
		return 0
	fi
	if [ -f "${codex_home}/.cc-plugin-codex.ready" ]; then
		return 0
	fi

	cat <<'EOF'

============================================================
 [skills] cc-plugin-codex (Codex -> Claude Code) is installed.

   One-time step: run   $cc:setup   inside Codex to finish wiring.
   After that you can use:  $cc:review  $cc:rescue  $cc:status ...

   To silence this reminder once done:
     touch ~/.codex/.cc-plugin-codex.ready
============================================================

EOF
}

USER_ID=${LOCAL_UID:-9001}
GROUP_ID=${LOCAL_GID:-9001}

if ! getent passwd ${LOCAL_WHOAMI} > /dev/null; then
	echo "Starting with UID : $USER_ID, GID: $GROUP_ID"
	test -z "${LOCAL_DOCKER_GID}" || groupmod -g "${LOCAL_DOCKER_GID}" docker
	useradd -u $USER_ID -o -m ${LOCAL_WHOAMI}
	groupmod -g $GROUP_ID ${LOCAL_WHOAMI}
	passwd -d ${LOCAL_WHOAMI}
	usermod -L ${LOCAL_WHOAMI}
	gpasswd -a ${LOCAL_WHOAMI} docker
	echo "${LOCAL_WHOAMI} ALL=NOPASSWD: ALL" | sudo EDITOR='tee -a' visudo
fi

if [ -S /var/run/docker.sock ]; then
	chown root:docker /var/run/docker.sock
	chmod 660 /var/run/docker.sock
fi

test -n "${SSH_AUTH_SOCK:-}" && grep -qxF "export SSH_AUTH_SOCK=${SSH_AUTH_SOCK}" /home/${LOCAL_WHOAMI}/.bashrc || \
	test -z "${SSH_AUTH_SOCK:-}" || sudo -u ${LOCAL_WHOAMI} echo "export SSH_AUTH_SOCK=${SSH_AUTH_SOCK}" >> /home/${LOCAL_WHOAMI}/.bashrc
test -n "${SSH_AUTH_SOCK:-}" && chown ${LOCAL_WHOAMI}:${LOCAL_WHOAMI} "${SSH_AUTH_SOCK}"
test -d /home/${LOCAL_WHOAMI}/.host.ssh && test ! -e /home/${LOCAL_WHOAMI}/.ssh && ln -s /home/${LOCAL_WHOAMI}/.host.ssh /home/${LOCAL_WHOAMI}/.ssh

chown -R ${LOCAL_WHOAMI}:${LOCAL_WHOAMI} /home/${LOCAL_WHOAMI} || :
setup_exec_audit
update_startup_tools

notice_codex_setup "$@"
exec_usershell "$@"
