"""The ``agent-defs`` command: install the hook, calibrate it, and report state.

Scanning never runs through this entry point. The harness launches the hook
itself with an isolated interpreter and a fixed argument list, so a console
script that is missing, shadowed or broken cannot take a scan down with it.
That separation is why this module can use ``argparse`` and a nonzero exit
code, both of which the hook path refuses.

``status`` is the command that answers what an install is actually doing:
which bundle it loaded, how many rules that leaves enabled on each surface,
what lane each of them can reach today, and whether the harness is registered
to call any of it.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

from . import __version__

USAGE_ERROR = 2
FAILED = 1


def _impl():
    from .hooks import _claude_code_impl as impl

    return impl


def _default_settings() -> Path:
    return Path.home() / ".claude" / "settings.json"


def _registration(impl, settings: Path) -> object:
    """Which harness events carry this package's own hook, or why we cannot say."""
    if not settings.exists():
        return "no settings file"
    try:
        value = json.loads(settings.read_text(encoding="utf-8-sig"))
        events = value.get("hooks", {}) if isinstance(value, dict) else {}
        found = [event for event in ("PreToolUse", "PostToolUse")
                 for group in events.get(event, [])
                 if any(impl.owned(hook) for hook in group.get("hooks", []))]
        return sorted(set(found)) or "not registered"
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        return f"unreadable: {type(exc).__name__}"


def _log_events(path: str) -> object:
    target = Path(path).expanduser()
    if not target.exists():
        return 0
    try:
        with target.open("rb") as stream:
            return sum(1 for line in stream if line.strip())
    except OSError as exc:
        return f"unreadable: {type(exc).__name__}"


def status(config_path: Path, settings: Path) -> dict:
    """What this install would do on the next tool call."""
    impl = _impl()
    config = impl.read_config(config_path)
    report = {"config": str(config_path), "config_exists": config_path.exists(),
              "settings": str(settings), "registered": _registration(impl, settings),
              "surfaces": list(config["surfaces"]),
              "sources": dict(config["sources"])}
    try:
        rules, bundle = impl.hook_rules(config)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        report["bundle"] = {"state": "unreadable", "error": f"{type(exc).__name__}: {exc}"}
        report["note"] = "every tool call reports incomplete coverage until this is fixed"
        return report
    report["bundle"] = bundle
    enabled = impl.active_rules(config, rules)
    lanes = impl.effective_lanes(config, enabled)
    by_surface: dict[str, int] = {}
    by_lane: dict[str, int] = {}
    for rule in enabled:
        by_surface[rule.surface.value] = by_surface.get(rule.surface.value, 0) + 1
        lane = lanes[rule.id][0].value
        by_lane[lane] = by_lane.get(lane, 0) + 1
    evidence = config.get("evidence") or {}
    report.update(rules_loaded=len(rules), rules_enabled=len(enabled),
                  enabled_by_surface=by_surface, enabled_by_lane=by_lane,
                  calibrated=evidence.get("fingerprint") == impl.fingerprint(enabled, config["surfaces"]),
                  log=config["log_path"], log_events=_log_events(config["log_path"]))
    return report


def _render(result: dict, as_json: bool, stream) -> None:
    if as_json:
        stream.write(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
        return
    # The installer already wrote the settings diff to stderr; repeating it here
    # as one field of a key/value listing would only make it unreadable.
    shown = {key: value for key, value in result.items() if key != "diff"}
    width = max((len(key) for key in shown), default=0)
    for key, value in shown.items():
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False)
        stream.write(f"{key.ljust(width)}  {value}\n")


def _parser() -> argparse.ArgumentParser:
    # ``--json`` lives on each subcommand rather than on both levels: argparse
    # lets a subparser's default overwrite a value the top level already set,
    # so a flag in both places would be silently dropped after the subcommand.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="emit the raw result object")
    common.add_argument("--config", type=Path, default=None,
                        help="this package's config (default: ~/.claude/agent-defs.json)")
    harness = argparse.ArgumentParser(add_help=False)
    harness.add_argument("--settings", type=Path, default=None,
                         help="harness settings file (default: ~/.claude/settings.json)")

    parser = argparse.ArgumentParser(prog="agent-defs", description=__doc__.splitlines()[0])
    parser.add_argument("--version", action="version", version=f"agent-defs {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text in (("install", "register the hook with a harness"),
                            ("uninstall", "remove this package's hook and nothing else")):
        action = sub.add_parser(name, help=help_text, parents=[common, harness])
        action.add_argument("--yes", action="store_true",
                            help="apply the change; without it the diff is printed and nothing is written")

    measure = sub.add_parser("calibrate", parents=[common],
                             help="measure the enabled bundle on a benign corpus")
    source = measure.add_mutually_exclusive_group(required=True)
    source.add_argument("--benign-dir", type=Path,
                        help="a directory of prose and source files to scan directly")
    source.add_argument("--report", type=Path,
                        help="an agent_defs.bench report over extracted tool traffic, "
                             "which is the population the OUT surface is defined over")
    measure.add_argument("--corpus-label", default=None,
                         help="required with --benign-dir; a report carries its own identity")
    measure.add_argument("--accept-pooled-bound", action="store_true",
                         help="record that you are gating on the pooled interval where the "
                              "benchmark gates on the worst per-stratum one. Never relaxes a "
                              "refusal about duplicate material or missing coverage.")

    sub.add_parser("status", parents=[common, harness],
                   help="what this install would do on the next tool call")

    export = sub.add_parser("export-bundle", parents=[common],
                            help="write the exact enabled set, for measuring")
    export.add_argument("--out", type=Path, required=True)

    lane = sub.add_parser("promote", parents=[common],
                          help="let one source act, up to what its measurement allows")
    lane.add_argument("--source", required=True)
    lane.add_argument("--lane", required=True, choices=["RECORD", "ADVISE", "DENY"])
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    impl = _impl()
    config = Path(args.config or impl.config_path()).expanduser().resolve()
    try:
        if args.command == "export-bundle":
            # calibrate refuses a report that does not cover every enabled rule,
            # and the enabled set is the starter rules plus the bundle minus
            # whatever the config gates out. Nothing else reproduces that set,
            # so measuring anything else produces a report calibrate rejects.
            from . import bundle as bundle_format

            settings_config = impl.read_config(config)
            enabled = impl.active_rules(settings_config, impl.hook_rules(settings_config)[0])
            written = bundle_format.write(args.out, enabled, exported_from=str(config),
                                          surfaces=list(settings_config["surfaces"]))
            result = {"agent_defs": "exported", "rules": len(enabled),
                      "out": str(args.out), "bytes": written}
        elif args.command == "promote":
            result = impl.promote(config, args.source, args.lane)
        elif args.command == "status":
            settings = Path(args.settings).expanduser().resolve() if args.settings else _default_settings()
            result = status(config, settings)
        elif args.command == "calibrate" and args.report:
            report = Path(args.report).expanduser().resolve()
            if not report.is_file():
                parser.exit(USAGE_ERROR, f"agent-defs: no such report: {report}\n")
            result = impl.calibrate_from_report(
                config, report, accept_pooled_bound=args.accept_pooled_bound)
        elif args.command == "calibrate":
            directory = Path(args.benign_dir).expanduser().resolve()
            if not directory.is_dir():
                parser.exit(USAGE_ERROR, f"agent-defs: no such directory: {directory}\n")
            if not args.corpus_label:
                parser.exit(USAGE_ERROR, "agent-defs: --corpus-label is required with --benign-dir\n")
            result = impl.calibrate(config, directory, args.corpus_label)
        else:
            settings = Path(args.settings).expanduser().resolve() if args.settings else _default_settings()
            result = impl.install(settings, config, uninstall=args.command == "uninstall",
                                  confirm=args.yes)
    except (OSError, ValueError, TypeError, KeyError, RuntimeError) as exc:
        sys.stderr.write(f"agent-defs: {type(exc).__name__}: {exc}\n")
        return FAILED
    _render(result, args.json, sys.stdout)
    return FAILED if result.get("agent_defs") == "confirmation_required" else 0


if __name__ == "__main__":
    raise SystemExit(main())
