"""Settings preservation is a byte contract, including unknown JSON values."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from agent_defs.hooks import _claude_code_impl as hook


def apply(settings, config, **kwargs):
    return hook.install(settings, config, confirm=True, **kwargs)


@pytest.fixture
def settings_copy(tmp_path):
    reference = Path.home() / ".claude" / "settings.json"
    guard = Path.home() / ".claude" / "hooks" / "guard.py"
    if not reference.is_file() or not guard.is_file():
        pytest.skip("reference machine only")
    before, guard_before = reference.read_bytes(), guard.read_bytes()
    target = tmp_path / "settings.json"
    target.write_bytes(before)
    yield target, tmp_path / "config.json", before
    assert reference.read_bytes() == before
    assert guard.read_bytes() == guard_before


def test_real_settings_additive_idempotent_byte_roundtrip(settings_copy):
    settings, config, before = settings_copy
    original = json.loads(before)
    result = apply(settings, config)
    installed = json.loads(settings.read_bytes())
    for event, groups in original["hooks"].items():
        assert installed["hooks"][event][:len(groups)] == groups
    guards = [g for g in original["hooks"]["PreToolUse"] if "guard.py" in json.dumps(g)]
    assert guards
    assert [g for g in installed["hooks"]["PreToolUse"] if "guard.py" in json.dumps(g)] == guards
    for event in ("PreToolUse", "PostToolUse"):
        assert len(installed["hooks"][event]) == len(original["hooks"][event]) + 1
        assert sum(hook.owned(h) for g in installed["hooks"][event] for h in g["hooks"]) == 1
    once = settings.read_bytes()
    assert Path(result["backup"]).read_bytes() == before
    apply(settings, config)
    assert settings.read_bytes() == once
    apply(settings, config, uninstall=True)
    assert settings.read_bytes() == before
    apply(settings, config, uninstall=True)
    assert settings.read_bytes() == before


def test_reference_guard_copy_still_requires_approval_with_escapes_off(settings_copy, tmp_path):
    settings, config, before = settings_copy
    copied_guard = tmp_path / "guard.py"
    copied_guard.write_bytes((Path.home() / ".claude" / "hooks" / "guard.py").read_bytes())
    apply(settings, config)
    env = dict(os.environ, AGENT_CONFIG_GATES="off", AGENT_STYLE_HOOK="off", AGENT_COMPOUND_CD_HOOK="off")
    result = subprocess.run([sys.executable, str(copied_guard)], cwd=tmp_path, env=env,
                            input=json.dumps({"tool_name": "Bash", "tool_input": {"command": "git push"}}),
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 0
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert all(group in json.loads(settings.read_bytes())["hooks"]["PreToolUse"]
               for group in json.loads(before)["hooks"]["PreToolUse"])
    apply(settings, config, uninstall=True)
    assert settings.read_bytes() == before


@pytest.mark.parametrize("raw", [
    b'{ "future" : {"scientific":1.2300e+04,"escaped":"\\u0061","array":[ 1, 2 ]}, "hooks": {"PreToolUse": []} }\r\n',
    b'\xef\xbb\xbf{\r\n\t"future": -0.0,\r\n\t"hooks": {}\r\n}\r\n',
    b'{"future": [true,null, "\\/" ]}',
    b'{"hooks":{"PreToolUse":[],"PostToolUse":[]}}',
    b'{}\n',
])
def test_unknown_settings_keep_their_original_bytes(tmp_path, raw):
    settings, config = tmp_path / "settings.json", tmp_path / "config.json"
    settings.write_bytes(raw)
    apply(settings, config)
    # Removing only the inserted ranges must recover every original byte.
    installed = settings.read_bytes()
    for token in (b'1.2300e+04', b'"\\u0061"', b'[ 1, 2 ]', b'-0.0', b'"\\/"'):
        if token in raw:
            assert token in installed
    apply(settings, config, uninstall=True)
    assert settings.read_bytes() == raw


@pytest.mark.parametrize("raw", [b'', b'{"hooks":', b'{"hooks":{', b'{"hooks":{},}',
    b'[]', b'{"hooks":null}', b'{"hooks":{"PreToolUse":null}}',
    b'{"hooks":{"PreToolUse":[{}]}}', b'{"hooks":{},"hooks":{}}', b'{"future":NaN}'])
def test_malformed_settings_refused_with_explanation(tmp_path, raw):
    settings, config = tmp_path / "settings.json", tmp_path / "config.json"
    settings.write_bytes(raw)
    with pytest.raises(ValueError, match="settings"):
        apply(settings, config)
    assert settings.read_bytes() == raw
    assert not config.exists()


def test_review_before_writing_and_backup_before_replace(tmp_path, capsys, monkeypatch):
    settings, config = tmp_path / "settings.json", tmp_path / "config.json"
    before = b'{"future":1.00}\n'
    settings.write_bytes(before)
    preview = hook.install(settings, config)
    assert preview["agent_defs"] == "confirmation_required"
    assert "+" in preview["diff"] and "PreToolUse" in preview["diff"]
    assert settings.read_bytes() == before and not config.exists()
    real_replace = hook.os.replace

    def checked(source, target):
        if Path(target) == settings:
            backups = list(tmp_path.glob("settings.json.agent-defs-*.bak"))
            assert any(p.read_bytes() == before for p in backups)
            assert "PreToolUse" in capsys.readouterr().err
        return real_replace(source, target)

    monkeypatch.setattr(hook.os, "replace", checked)
    apply(settings, config)


def test_uninstall_keeps_later_edits_and_mixed_group_metadata(tmp_path):
    settings, config = tmp_path / "settings.json", tmp_path / "config.json"
    guard = {"type": "command", "command": "python guard.py", "future": [1, 2]}
    original = {"hooks": {"PreToolUse": [{"matcher": "Bash", "future": {"x": 1},
                                           "hooks": [guard, hook.hook_spec(config)]}]}}
    settings.write_text(json.dumps(original), encoding="utf-8")
    apply(settings, config, uninstall=True)
    result = json.loads(settings.read_bytes())
    assert result["hooks"]["PreToolUse"] == [{"matcher": "Bash", "future": {"x": 1}, "hooks": [guard]}]


def test_uninstall_preserves_settings_changed_after_install(tmp_path):
    settings, config = tmp_path / "settings.json", tmp_path / "config.json"
    settings.write_bytes(b'{"future":1.00}')
    apply(settings, config)
    settings.write_bytes(settings.read_bytes().replace(b'"future":1.00', b'"future":2.00'))
    apply(settings, config, uninstall=True)
    assert settings.read_bytes() == b'{"future":2.00}'


def test_duplicate_legacy_entries_merge_beside_guard_once(tmp_path):
    settings, config = tmp_path / "settings.json", tmp_path / "config.json"
    executable, *args = hook.hook_argv(config)
    legacy = {"type": "command", "command": executable, "args": args, "timeout": 2}
    guard = {"type": "command", "command": "python guard.py"}
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [legacy, guard]}, {"matcher": "*", "hooks": [legacy]}]}}))
    apply(settings, config)
    once = settings.read_bytes()
    groups = json.loads(once)["hooks"]["PreToolUse"]
    assert groups[0] == {"matcher": "Bash", "hooks": [guard]}
    assert sum(hook.owned(h) for g in groups for h in g["hooks"]) == 1
    apply(settings, config)
    assert settings.read_bytes() == once


def test_backup_failure_cannot_change_settings_or_create_config(tmp_path, monkeypatch):
    settings, config = tmp_path / "settings.json", tmp_path / "config.json"
    settings.write_bytes(b'{}')

    def fail(**kwargs):
        raise OSError("backup volume unavailable")

    monkeypatch.setattr(hook.tempfile, "mkstemp", fail)
    with pytest.raises(OSError, match="backup"):
        apply(settings, config)
    assert settings.read_bytes() == b'{}' and not config.exists()


def test_intervening_editor_change_is_not_overwritten(tmp_path, monkeypatch):
    settings, config = tmp_path / "settings.json", tmp_path / "config.json"
    settings.write_bytes(b'{}')
    atomic = hook.atomic_json

    def edited(path, value):
        atomic(path, value)
        settings.write_bytes(b'{"concurrent":true}')

    monkeypatch.setattr(hook, "atomic_json", edited)
    with pytest.raises(RuntimeError, match="settings changed"):
        apply(settings, config)
    assert settings.read_bytes() == b'{"concurrent":true}'


def test_unknown_receipt_is_not_overwritten(tmp_path):
    settings, config = tmp_path / "settings.json", tmp_path / "config.json"
    settings.write_bytes(b'{}')
    receipt = tmp_path / "settings.json.agent-defs-state.json"
    receipt.write_bytes(b'{"user-owned":true}')
    with pytest.raises(ValueError, match="receipt"):
        apply(settings, config)
    assert receipt.read_bytes() == b'{"user-owned":true}'
    assert settings.read_bytes() == b'{}' and not config.exists()
