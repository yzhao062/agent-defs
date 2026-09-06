"""The ``agent-defs`` command, and what its report is allowed to claim."""
from dataclasses import replace
import json

import pytest

from agent_defs import bundle, cli
from agent_defs.builtin import STARTER_RULES
from agent_defs.hooks import _claude_code_impl as impl


@pytest.fixture
def paths(tmp_path):
    config = tmp_path / "agent-defs.json"
    settings = tmp_path / "settings.json"
    value = impl.default_config()
    value["log_path"] = str(tmp_path / "findings.jsonl")
    value["bundle"] = ""
    config.write_text(json.dumps(value), encoding="utf-8")
    return config, settings


def test_the_entry_point_the_wheel_advertises_exists():
    # pyproject declares agent-defs = "agent_defs.cli:main". A wheel whose
    # console script imports a module nobody wrote installs a command that
    # crashes on first use, which is what this file was added to end. Read as
    # text rather than through tomllib, which arrived in 3.11 and this package
    # supports 3.9.
    import re
    from pathlib import Path

    root = Path(impl.__file__).resolve().parents[3]
    declared = (root / "pyproject.toml").read_text(encoding="utf-8")
    found = re.search(r'^agent-defs\s*=\s*"([^"]+)"', declared, re.MULTILINE)
    assert found, "pyproject no longer declares the agent-defs console script"
    module, _, attribute = found.group(1).partition(":")
    assert module == cli.__name__
    assert callable(getattr(cli, attribute))


def test_status_reports_the_starter_set_when_a_config_asks_for_it(paths, capsys):
    config, settings = paths
    assert cli.main(["status", "--config", str(config), "--settings", str(settings), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)

    assert report["bundle"] == {"bundle": "starter_only"}
    assert report["rules_loaded"] == len(STARTER_RULES)
    assert report["registered"] == "no settings file"
    assert report["calibrated"] is False
    assert report["enabled_by_lane"] == {"RECORD": len(STARTER_RULES)}


def test_status_counts_the_bundle_it_would_actually_load(paths, tmp_path, capsys):
    config, settings = paths
    elsewhere = tmp_path / "custom.json"
    carried = [replace(rule, id=rule.id.replace("builtin:", "atr:"), source="atr")
               for rule in STARTER_RULES]
    bundle.write(elsewhere, carried, source_rev="c" * 40)
    value = json.loads(config.read_text(encoding="utf-8"))
    value["bundle"] = str(elsewhere)
    config.write_text(json.dumps(value), encoding="utf-8")

    assert cli.main(["status", "--config", str(config), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["bundle"]["bundle"] == "loaded"
    assert report["bundle"]["source_rev"] == "c" * 40
    # The starter set is always present, so the report counts the bundle on top
    # of it rather than in place of it.
    assert report["rules_loaded"] == len(carried) + len(STARTER_RULES)
    assert report["enabled_by_surface"] == {"OUT": len(carried) + len(STARTER_RULES)}


def test_status_says_a_corrupt_bundle_is_corrupt(paths, tmp_path, capsys):
    config, _ = paths
    broken = tmp_path / "broken.json"
    broken.write_text("{ not json", encoding="utf-8")
    value = json.loads(config.read_text(encoding="utf-8"))
    value["bundle"] = str(broken)
    config.write_text(json.dumps(value), encoding="utf-8")

    assert cli.main(["status", "--config", str(config), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["bundle"]["state"] == "unreadable"
    assert "rules_enabled" not in report


def test_install_writes_nothing_without_the_confirming_flag(paths, capsys):
    config, settings = paths
    code = cli.main(["install", "--config", str(config), "--settings", str(settings)])
    captured = capsys.readouterr()

    assert code == cli.FAILED
    assert not settings.exists()
    assert "confirmation_required" in captured.out
    assert "PostToolUse" in captured.err  # the proposed diff


def test_install_then_status_reports_the_registration(paths, capsys):
    config, settings = paths
    assert cli.main(["install", "--config", str(config), "--settings", str(settings), "--yes"]) == 0
    capsys.readouterr()

    assert cli.main(["status", "--config", str(config), "--settings", str(settings), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["registered"] == ["PostToolUse", "PreToolUse"]

    assert cli.main(["uninstall", "--config", str(config), "--settings", str(settings), "--yes"]) == 0
    capsys.readouterr()
    assert cli.main(["status", "--config", str(config), "--settings", str(settings), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["registered"] == "not registered"


def test_an_unreadable_config_fails_rather_than_falling_back_to_defaults(tmp_path, capsys):
    config = tmp_path / "agent-defs.json"
    config.write_text(json.dumps({"version": 2}), encoding="utf-8")
    assert cli.main(["status", "--config", str(config)]) == cli.FAILED
    assert "unsupported config version" in capsys.readouterr().err


def test_a_missing_benign_directory_is_a_usage_error(paths, tmp_path):
    config, _ = paths
    with pytest.raises(SystemExit) as raised:
        cli.main(["calibrate", "--config", str(config), "--corpus-label", "x",
                  "--benign-dir", str(tmp_path / "absent")])
    assert raised.value.code == cli.USAGE_ERROR
