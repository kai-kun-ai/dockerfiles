#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ai-audit - audit report generator for the claude-codex image.

WHY THIS EXISTS (issue #280: "add an audit feature to the codex/claude images")
-------------------------------------------------------------------------------
Goal: record, at the OS level, the work that was actually done inside the image,
and render it in a graphically understandable report.

True kernel syscall auditing (``auditd`` / eBPF / process accounting) is *not*
available inside an unprivileged container: those subsystems are **not
namespaced** and need ``CAP_AUDIT_CONTROL`` / ``CAP_BPF`` / ``CAP_SYS_PACCT`` (or
``--privileged``), which the ``make target=claude`` / ``make target=codex``
sandbox deliberately does not grant. So we capture at the next level down --
every ``execve`` -- with **snoopy**, a ~20-year-old LD_PRELOAD command logger
enabled image-wide via ``/etc/ld.so.preload``. It needs no privileges, records
the command actually run (argv, cwd, user, time) independently of the agent, and
is the mature in-container answer to "what commands were executed".

This tool reads two complementary sources and unifies them:

    exec (snoopy) : /var/log/ai-audit/exec.log  -- OS-level, agent-independent
    Codex         : ~/.codex/sessions/**/*.jsonl (also mined by ``codex-monitor``)
    Claude Code   : ~/.claude/projects/**/*.jsonl

The session logs add structure the exec stream lacks (which agent, file edits,
per-session grouping); snoopy adds the independent ground truth. It renders:

  * a concise **text summary** on the terminal, and
  * a self-contained, dependency-free **HTML report** ("graphically
    understandable", per the issue) with CSS-only charts -- no JavaScript, no CDN,
    so it opens offline and ages well.

Pure standard library (the image already builds CPython); nothing to install.

USAGE
-----
    ai-audit                       # text summary + HTML report (~/.ai-audit/...)
    ai-audit --agent codex         # only Codex sessions
    ai-audit --since 7d            # only events from the last 7 days
    ai-audit --html report.html    # write the HTML report to a chosen path
    ai-audit --text-only           # no HTML, just the terminal summary
    ai-audit --json                # machine-readable summary on stdout
    ai-audit --help

It is best-effort by design: unreadable or unexpected log lines are skipped, and
an empty trail is reported politely rather than treated as an error.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

KIND_COMMAND = "command"
KIND_WRITE = "file-write"
KIND_READ = "file-read"
KIND_OTHER = "other"

KIND_LABELS = {
    KIND_COMMAND: "commands",
    KIND_WRITE: "file writes",
    KIND_READ: "file reads",
    KIND_OTHER: "other actions",
}


class Event:
    """A single audited action extracted from an agent session log."""

    __slots__ = ("ts", "agent", "session", "kind", "summary", "program", "cwd")

    def __init__(self, ts, agent, session, kind, summary, program="", cwd=""):
        self.ts = ts            # datetime (UTC) or None
        self.agent = agent      # "codex" | "claude"
        self.session = session  # session id / file label
        self.kind = kind        # KIND_*
        self.summary = summary  # command line or file path
        self.program = program  # argv0 basename for commands
        self.cwd = cwd


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_ts(value):
    """Parse an ISO-8601 timestamp (tolerating a trailing 'Z') to aware UTC."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        # Last resort: epoch seconds as a string/number.
        try:
            return datetime.fromtimestamp(float(text), tz=timezone.utc)
        except (ValueError, OSError):
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhdw])\s*$", re.IGNORECASE)
_DURATION_UNITS = {
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
    "w": 604800,
}


def parse_since(value):
    """Turn '7d' / '24h' / '30m' into a cutoff aware-UTC datetime, or None."""
    if not value:
        return None
    match = _DURATION_RE.match(value)
    if not match:
        raise ValueError(
            "invalid --since value %r (use forms like 30m, 24h, 7d, 2w)" % value
        )
    seconds = int(match.group(1)) * _DURATION_UNITS[match.group(2).lower()]
    return datetime.now(timezone.utc) - timedelta(seconds=seconds)


# Leading "VAR=value" assignments and a few transparent prefixes we strip when
# guessing the program name that a command line actually runs.
_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_TRANSPARENT = {"sudo", "command", "env", "exec", "nohup", "time", "nice", "ionice"}


def command_to_string(command):
    """Normalise a command (str or argv list) into a single display string."""
    if isinstance(command, str):
        return command.strip()
    if isinstance(command, (list, tuple)):
        parts = [str(p) for p in command]
        # Agents wrap shell calls as ["bash", "-lc", "<script>"]; show the script.
        if len(parts) >= 3 and os.path.basename(parts[0]) in ("bash", "sh", "zsh") \
                and parts[1] in ("-lc", "-c", "-lic"):
            return parts[2].strip()
        return " ".join(parts).strip()
    return ""


def program_name(command_str):
    """Best-effort argv0 basename for command-frequency grouping."""
    if not command_str:
        return "?"
    # Only look at the first stage of a pipeline / sequence.
    head = re.split(r"[\n;|&]", command_str, maxsplit=1)[0].strip()
    for token in head.split():
        if _ASSIGN_RE.match(token):
            continue  # skip inline env assignment
        base = os.path.basename(token)
        if base in _TRANSPARENT:
            continue  # skip sudo/env/... wrappers
        return base
    return "?"


def iter_jsonl(path):
    """Yield parsed JSON objects from a .jsonl file, skipping bad lines."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except (ValueError, TypeError):
                    continue
    except OSError:
        return


def find_logs(root, suffix=".jsonl"):
    """Return every *.jsonl file under ``root`` (sorted, mtime-stable)."""
    results = []
    if not root or not os.path.isdir(root):
        return results
    for dirpath, _dirnames, filenames in os.walk(root):
        if "__MACOSX" in dirpath:
            continue
        for name in filenames:
            if name.endswith(suffix):
                results.append(os.path.join(dirpath, name))
    results.sort()
    return results


# ---------------------------------------------------------------------------
# Codex parsing  (~/.codex/sessions/**/*.jsonl)
# ---------------------------------------------------------------------------

def _codex_payload(obj):
    """Codex lines are usually {"type": .., "payload": {..}} but tolerate flat."""
    payload = obj.get("payload")
    return payload if isinstance(payload, dict) else obj


def parse_codex_file(path):
    session = os.path.splitext(os.path.basename(path))[0]
    cwd = ""
    for obj in iter_jsonl(path):
        if not isinstance(obj, dict):
            continue
        line_ts = parse_ts(obj.get("timestamp"))
        otype = obj.get("type")
        payload = _codex_payload(obj)
        ptype = payload.get("type") if isinstance(payload, dict) else None

        # Session metadata: capture cwd for later events on the same session.
        if otype == "session_meta" or ptype == "session_meta":
            cwd = payload.get("cwd", cwd) or cwd
            continue

        command = None
        kind = KIND_COMMAND

        if ptype in ("function_call", "local_shell_call", "custom_tool_call"):
            name = payload.get("name", "")
            if name in ("apply_patch", "applypatch"):
                kind = KIND_WRITE
            # arguments may be a JSON string or already-decoded dict.
            args = payload.get("arguments", payload.get("action"))
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except (ValueError, TypeError):
                    args = {"command": args}
            if isinstance(args, dict):
                command = args.get("command", args.get("cmd"))
                if command is None and kind == KIND_WRITE:
                    command = "apply_patch: " + str(args.get("path", "")).strip()
            elif args is not None:
                command = args
            if command is None and name:
                command = name
        elif ptype in ("exec_command_begin", "exec_command"):
            command = payload.get("command")
            cwd = payload.get("cwd", cwd) or cwd

        if command is None:
            continue

        summary = command_to_string(command)
        if not summary:
            continue
        prog = program_name(summary) if kind == KIND_COMMAND else ""
        yield Event(line_ts, "codex", session, kind, summary, prog, cwd)


# ---------------------------------------------------------------------------
# Claude Code parsing  (~/.claude/projects/**/*.jsonl)
# ---------------------------------------------------------------------------

# Claude tool names mapped to the audit kind they represent.
_CLAUDE_WRITE_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit", "Update"}
_CLAUDE_READ_TOOLS = {"Read", "NotebookRead"}


def parse_claude_file(path):
    session = os.path.splitext(os.path.basename(path))[0]
    for obj in iter_jsonl(path):
        if not isinstance(obj, dict):
            continue
        if obj.get("type") != "assistant":
            continue
        line_ts = parse_ts(obj.get("timestamp"))
        cwd = obj.get("cwd", "") or ""
        sid = obj.get("sessionId") or session
        message = obj.get("message")
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "tool_use":
                continue
            name = block.get("name", "")
            tool_input = block.get("input")
            tool_input = tool_input if isinstance(tool_input, dict) else {}
            if name == "Bash":
                summary = str(tool_input.get("command", "")).strip()
                if not summary:
                    continue
                yield Event(line_ts, "claude", sid, KIND_COMMAND,
                            summary, program_name(summary), cwd)
            elif name in _CLAUDE_WRITE_TOOLS:
                target = str(tool_input.get("file_path")
                             or tool_input.get("notebook_path") or "").strip()
                if not target:
                    continue
                yield Event(line_ts, "claude", sid, KIND_WRITE,
                            "%s %s" % (name, target), "", cwd)
            elif name in _CLAUDE_READ_TOOLS:
                target = str(tool_input.get("file_path")
                             or tool_input.get("notebook_path") or "").strip()
                if not target:
                    continue
                yield Event(line_ts, "claude", sid, KIND_READ,
                            "%s %s" % (name, target), "", cwd)


# ---------------------------------------------------------------------------
# OS-level exec auditing  (snoopy log)
# ---------------------------------------------------------------------------
#
# snoopy (an LD_PRELOAD execve logger enabled image-wide via /etc/ld.so.preload)
# records every command actually executed inside the container -- independently
# of what the agents choose to write to their own logs. We configure it (see
# dockerfiles/claude-codex/snoopy.ini) to emit one pipe-delimited line per exec:
#
#     snoopy-audit|<unix_ts>|<uid>|<username>|<cwd>|<cmdline>
#
# The cmdline is always last so it may safely contain '|' (split is bounded).
EXEC_MARKER = "snoopy-audit|"


def parse_exec_file(path):
    session_default = "exec"
    try:
        handle = open(path, "r", encoding="utf-8", errors="replace")
    except OSError:
        return
    with handle:
        for raw in handle:
            if not raw.startswith(EXEC_MARKER):
                continue
            # marker | ts | uid | username | cwd | cmdline(may contain '|')
            parts = raw.rstrip("\n").split("|", 5)
            if len(parts) < 6:
                continue
            _marker, ts_s, _uid, username, cwd, cmdline = parts
            cmdline = cmdline.strip()
            if not cmdline:
                continue
            yield Event(parse_ts(ts_s), "exec", username or session_default,
                        KIND_COMMAND, cmdline, program_name(cmdline), cwd)


def resolve_exec_log(explicit):
    """Pick the snoopy exec log: explicit path, else first that exists."""
    if explicit:
        return explicit
    home = os.path.expanduser("~")
    for candidate in ("/var/log/ai-audit/exec.log",
                      os.path.join(home, ".ai-audit", "exec.log"),
                      "/var/log/snoopy.log"):
        if os.path.isfile(candidate):
            return candidate
    return None


# ---------------------------------------------------------------------------
# Collection + summary
# ---------------------------------------------------------------------------

def collect_events(args):
    events = []
    sources = {"codex": 0, "claude": 0, "exec": 0}

    if args.agent in ("all", "codex"):
        for path in find_logs(args.codex_dir):
            sources["codex"] += 1
            events.extend(parse_codex_file(path))
    if args.agent in ("all", "claude"):
        for path in find_logs(args.claude_dir):
            sources["claude"] += 1
            events.extend(parse_claude_file(path))
    if args.agent in ("all", "exec"):
        exec_log = resolve_exec_log(args.exec_log)
        if exec_log and os.path.isfile(exec_log):
            sources["exec"] += 1
            events.extend(parse_exec_file(exec_log))

    cutoff = parse_since(args.since)
    if cutoff is not None:
        events = [e for e in events if e.ts is None or e.ts >= cutoff]

    # Stable chronological order; undated events sort last but keep file order.
    events.sort(key=lambda e: (e.ts is None, e.ts or datetime.max.replace(tzinfo=timezone.utc)))
    return events, sources


def summarize(events, top):
    by_agent = Counter(e.agent for e in events)
    by_kind = Counter(e.kind for e in events)
    sessions = defaultdict(lambda: {"agent": "", "count": 0, "first": None, "last": None})
    programs = Counter()
    hours = Counter()
    dated = [e for e in events if e.ts is not None]

    for e in events:
        s = sessions[(e.agent, e.session)]
        s["agent"] = e.agent
        s["count"] += 1
        if e.ts is not None:
            if s["first"] is None or e.ts < s["first"]:
                s["first"] = e.ts
            if s["last"] is None or e.ts > s["last"]:
                s["last"] = e.ts
        if e.kind == KIND_COMMAND and e.program:
            programs[e.program] += 1
        if e.ts is not None:
            hours[e.ts.strftime("%Y-%m-%d %H:00")] += 1

    return {
        "total": len(events),
        "by_agent": by_agent,
        "by_kind": by_kind,
        "sessions": sessions,
        "programs": programs.most_common(top),
        "hours": sorted(hours.items()),
        "first": min((e.ts for e in dated), default=None),
        "last": max((e.ts for e in dated), default=None),
        "n_sessions": len(sessions),
    }


# ---------------------------------------------------------------------------
# Rendering: text
# ---------------------------------------------------------------------------

def fmt_ts(dt):
    return dt.strftime("%Y-%m-%d %H:%M") if dt else "-"


def render_text(summary, sources):
    out = []
    out.append("=== AI activity audit ===")
    out.append("scanned : codex=%d claude=%d session log(s), exec=%d snoopy log(s)"
               % (sources["codex"], sources["claude"], sources["exec"]))
    out.append("window  : %s -> %s"
               % (fmt_ts(summary["first"]), fmt_ts(summary["last"])))
    out.append("sessions: %d   actions: %d"
               % (summary["n_sessions"], summary["total"]))

    if summary["total"] == 0:
        out.append("")
        out.append("No agent activity found. Nothing to audit yet.")
        return "\n".join(out)

    out.append("")
    out.append("by agent : " + ", ".join(
        "%s=%d" % (a, c) for a, c in sorted(summary["by_agent"].items())) or "-")
    out.append("by action: " + ", ".join(
        "%s=%d" % (KIND_LABELS.get(k, k), c)
        for k, c in sorted(summary["by_kind"].items())))

    if summary["programs"]:
        out.append("")
        out.append("top commands:")
        width = max(len(p) for p, _ in summary["programs"])
        top_n = summary["programs"][0][1]
        for prog, count in summary["programs"]:
            bar = "#" * max(1, int(round(count / top_n * 24)))
            out.append("  %-*s %5d  %s" % (width, prog, count, bar))

    out.append("")
    out.append("sessions:")
    ranked = sorted(summary["sessions"].items(),
                    key=lambda kv: kv[1]["count"], reverse=True)
    for (agent, sid), info in ranked[:20]:
        out.append("  [%-6s] %-38s %4d actions  %s -> %s"
                   % (agent, sid[:38], info["count"],
                      fmt_ts(info["first"]), fmt_ts(info["last"])))
    if len(ranked) > 20:
        out.append("  ... and %d more session(s)" % (len(ranked) - 20))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Rendering: HTML  (self-contained, CSS-only charts, no JS/CDN)
# ---------------------------------------------------------------------------

HTML_STYLE = """
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
  margin:0;padding:2rem;background:#0f1117;color:#e6e6e6}
h1{font-size:1.5rem;margin:0 0 .25rem}
h2{font-size:1.05rem;margin:2rem 0 .75rem;border-bottom:1px solid #2a2f3a;padding-bottom:.3rem}
.muted{color:#9aa4b2}
.cards{display:flex;flex-wrap:wrap;gap:1rem;margin-top:1rem}
.card{background:#171a22;border:1px solid #2a2f3a;border-radius:10px;padding:1rem 1.25rem;min-width:9rem}
.card .n{font-size:1.8rem;font-weight:700}
.card .l{color:#9aa4b2;font-size:.8rem;text-transform:uppercase;letter-spacing:.03em}
table{border-collapse:collapse;width:100%;margin-top:.5rem}
th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #232833;vertical-align:top}
th{color:#9aa4b2;font-weight:600;font-size:.8rem;text-transform:uppercase;letter-spacing:.03em}
td.cmd{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  white-space:pre-wrap;word-break:break-word;max-width:60ch}
.bar-row{display:flex;align-items:center;gap:.6rem;margin:.2rem 0}
.bar-row .name{flex:0 0 12rem;font-family:ui-monospace,monospace;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar-row .track{flex:1;background:#171a22;border-radius:5px;overflow:hidden}
.bar-row .fill{height:1.1rem;background:linear-gradient(90deg,#4f8cff,#6ad0ff);border-radius:5px}
.bar-row .val{flex:0 0 3.5rem;text-align:right;color:#9aa4b2}
.spark{display:flex;align-items:flex-end;gap:2px;height:90px;margin-top:.5rem;
  border-bottom:1px solid #2a2f3a;padding-bottom:2px}
.spark .b{flex:1;min-width:2px;background:linear-gradient(180deg,#6ad0ff,#4f8cff);border-radius:2px 2px 0 0}
.pill{display:inline-block;padding:.05rem .5rem;border-radius:999px;font-size:.78rem;
  border:1px solid #2a2f3a;background:#171a22}
.agent-codex{color:#ffcf66}.agent-claude{color:#c08cff}.agent-exec{color:#6ad08a}
footer{margin-top:2.5rem;color:#6b7280;font-size:.8rem}
"""


def _bar_rows(pairs):
    if not pairs:
        return '<p class="muted">none</p>'
    top = max(c for _, c in pairs) or 1
    rows = []
    for name, count in pairs:
        pct = max(2, int(round(count / top * 100)))
        rows.append(
            '<div class="bar-row"><span class="name" title="{n}">{n}</span>'
            '<span class="track"><span class="fill" style="width:{p}%"></span></span>'
            '<span class="val">{c}</span></div>'.format(
                n=html.escape(name), p=pct, c=count))
    return "\n".join(rows)


def _spark(hours):
    if not hours:
        return '<p class="muted">no timestamped activity</p>'
    top = max(c for _, c in hours) or 1
    bars = []
    for label, count in hours:
        h = max(3, int(round(count / top * 86)))
        bars.append('<div class="b" style="height:{h}px" title="{l}: {c}"></div>'.format(
            h=h, l=html.escape(label), c=count))
    span = "%s &rarr; %s" % (html.escape(hours[0][0]), html.escape(hours[-1][0]))
    return '<div class="spark">%s</div><p class="muted">%s (per hour)</p>' % (
        "\n".join(bars), span)


def _agent_class(agent):
    return {"codex": "agent-codex", "claude": "agent-claude",
            "exec": "agent-exec"}.get(agent, "agent-claude")


def render_html(summary, events, sources, generated_at, max_rows=500):
    by_kind = summary["by_kind"]
    cards = [
        ("actions", summary["total"]),
        ("sessions", summary["n_sessions"]),
        ("commands", by_kind.get(KIND_COMMAND, 0)),
        ("file writes", by_kind.get(KIND_WRITE, 0)),
        ("file reads", by_kind.get(KIND_READ, 0)),
    ]
    card_html = "\n".join(
        '<div class="card"><div class="n">{n}</div><div class="l">{l}</div></div>'.format(
            n=v, l=html.escape(l)) for l, v in cards)

    agent_pills = " ".join(
        '<span class="pill {cls}">{a}: {c}</span>'.format(
            cls=_agent_class(a), a=html.escape(a), c=c)
        for a, c in sorted(summary["by_agent"].items())) or \
        '<span class="muted">none</span>'

    # Sessions table (busiest first).
    ranked = sorted(summary["sessions"].items(),
                    key=lambda kv: kv[1]["count"], reverse=True)
    sess_rows = []
    for (agent, sid), info in ranked[:100]:
        sess_rows.append(
            "<tr><td><span class='{cls}'>{a}</span></td><td class='cmd'>{s}</td>"
            "<td>{c}</td><td>{f}</td><td>{l}</td></tr>".format(
                cls=_agent_class(agent), a=html.escape(agent),
                s=html.escape(sid), c=info["count"],
                f=fmt_ts(info["first"]), l=fmt_ts(info["last"])))
    sess_table = "\n".join(sess_rows) or \
        "<tr><td colspan='5' class='muted'>none</td></tr>"

    # Full action log (most recent first, capped).
    log_rows = []
    for e in reversed(events[-max_rows:]):
        log_rows.append(
            "<tr><td>{t}</td><td><span class='{cls}'>{a}</span></td>"
            "<td>{k}</td><td class='cmd'>{s}</td></tr>".format(
                t=fmt_ts(e.ts), cls=_agent_class(e.agent),
                a=html.escape(e.agent), k=html.escape(e.kind),
                s=html.escape(e.summary)))
    log_table = "\n".join(log_rows) or \
        "<tr><td colspan='4' class='muted'>none</td></tr>"
    capped_note = ""
    if len(events) > max_rows:
        capped_note = ('<p class="muted">showing the most recent %d of %d '
                       'actions</p>' % (max_rows, len(events)))

    return """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI activity audit</title>
<style>{style}</style></head><body>
<h1>AI activity audit</h1>
<p class="muted">generated {gen} &middot; sources: codex={sc} / claude={cl} session log(s),
exec={ex} snoopy log(s) &middot; window {first} &rarr; {last}</p>
<div class="cards">{cards}</div>

<h2>By agent</h2>
<p>{agents}</p>

<h2>Top commands</h2>
{bars}

<h2>Activity timeline</h2>
{spark}

<h2>Sessions</h2>
<table><thead><tr><th>agent</th><th>session</th><th>actions</th>
<th>first</th><th>last</th></tr></thead><tbody>
{sessions}
</tbody></table>

<h2>Action log</h2>
{capped}
<table><thead><tr><th>time</th><th>agent</th><th>kind</th><th>detail</th></tr></thead><tbody>
{log}
</tbody></table>

<footer>ai-audit &middot; built from Codex/Claude Code session logs &middot;
no telemetry, fully offline</footer>
</body></html>
""".format(
        style=HTML_STYLE, gen=html.escape(generated_at),
        sc=sources["codex"], cl=sources["claude"], ex=sources["exec"],
        first=fmt_ts(summary["first"]), last=fmt_ts(summary["last"]),
        cards=card_html, agents=agent_pills,
        bars=_bar_rows(summary["programs"]),
        spark=_spark(summary["hours"]),
        sessions=sess_table, capped=capped_note, log=log_table)


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def render_json(summary, sources):
    return json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources": sources,
        "total": summary["total"],
        "sessions": summary["n_sessions"],
        "window": {
            "first": summary["first"].isoformat() if summary["first"] else None,
            "last": summary["last"].isoformat() if summary["last"] else None,
        },
        "by_agent": dict(summary["by_agent"]),
        "by_kind": {KIND_LABELS.get(k, k): c for k, c in summary["by_kind"].items()},
        "top_commands": [{"command": p, "count": c} for p, c in summary["programs"]],
    }, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    home = os.path.expanduser("~")
    parser = argparse.ArgumentParser(
        prog="ai-audit",
        description="Audit report for Codex / Claude Code activity, built from "
                    "the agents' own session logs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--agent", choices=("all", "codex", "claude", "exec"),
                        default="all",
                        help="which source to include: codex/claude session logs, "
                             "exec (snoopy OS-level command log), or all")
    parser.add_argument("--since", default=None, metavar="DURATION",
                        help="only events newer than e.g. 30m, 24h, 7d, 2w")
    parser.add_argument("--top", type=int, default=15, metavar="N",
                        help="number of commands in the frequency chart")
    parser.add_argument("--html", nargs="?", const="", default=None,
                        metavar="PATH",
                        help="write the HTML report (default path if PATH omitted)")
    parser.add_argument("--text-only", action="store_true",
                        help="do not write an HTML report")
    parser.add_argument("--json", action="store_true",
                        help="print a machine-readable JSON summary instead of text")
    parser.add_argument("--codex-dir", default=os.path.join(home, ".codex", "sessions"),
                        help="Codex sessions directory")
    parser.add_argument("--claude-dir", default=os.path.join(home, ".claude", "projects"),
                        help="Claude Code projects directory")
    parser.add_argument("--exec-log", default=None, metavar="PATH",
                        help="snoopy exec-audit log (default: "
                             "/var/log/ai-audit/exec.log)")
    return parser


def default_html_path():
    base = os.path.join(os.path.expanduser("~"), ".ai-audit")
    try:
        os.makedirs(base, exist_ok=True)
    except OSError:
        base = os.getcwd()
    return os.path.join(base, "ai-audit-report.html")


def main(argv=None):
    args = build_parser().parse_args(argv)

    try:
        events, sources = collect_events(args)
    except ValueError as exc:
        print("ai-audit: %s" % exc, file=sys.stderr)
        return 2

    summary = summarize(events, args.top)

    if args.json:
        print(render_json(summary, sources))
    else:
        print(render_text(summary, sources))

    # Decide whether to emit HTML. Default is yes unless --text-only or --json.
    want_html = not args.text_only and not args.json
    html_path = None
    if args.html is not None:
        want_html = True
        html_path = args.html or None
    if want_html:
        if not html_path:
            html_path = default_html_path()
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        try:
            with open(html_path, "w", encoding="utf-8") as handle:
                handle.write(render_html(summary, events, sources, generated_at))
            if not args.json:
                print("\nHTML report: %s" % html_path)
        except OSError as exc:
            print("ai-audit: could not write HTML report: %s" % exc,
                  file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
