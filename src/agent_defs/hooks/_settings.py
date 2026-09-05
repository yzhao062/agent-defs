"""Surgical JSON edits: preserve all text outside the entries we own."""
from dataclasses import dataclass
import json


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate object key")
        result[key] = value
    return result


def _constant(value):
    raise ValueError("non-JSON numeric constant")


def validate(text):
    try:
        value = json.loads(text[1:] if text.startswith("\ufeff") else text,
                           object_pairs_hook=_pairs, parse_constant=_constant)
        if not isinstance(value, dict) or not isinstance(value.get("hooks", {}), dict):
            raise ValueError("root and hooks must be objects")
        for event in ("PreToolUse", "PostToolUse"):
            groups = value.get("hooks", {}).get(event, [])
            if not isinstance(groups, list):
                raise ValueError(f"{event} must be an array")
            for group in groups:
                if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
                    raise ValueError(f"{event} contains an invalid hook group")
                if any(not isinstance(h, dict) for h in group["hooks"]):
                    raise ValueError(f"{event} contains a non-object hook")
        return value
    except (ValueError, RecursionError) as exc:
        raise ValueError(f"invalid settings: {exc}") from exc


@dataclass
class Node:
    start: int
    end: int
    children: list


class Document:
    def __init__(self, text):
        self.text = text
        self.value = validate(text)
        self.root = self._node(self._space(1 if text.startswith("\ufeff") else 0))

    def _space(self, pos):
        while pos < len(self.text) and self.text[pos] in " \t\r\n":
            pos += 1
        return pos

    def _node(self, start):
        text = self.text
        children = []
        if text[start] not in "[{":
            _, end = json.JSONDecoder().raw_decode(text, start)
            return Node(start, end, children)
        close = "]" if text[start] == "[" else "}"
        pos = self._space(start + 1)
        while text[pos] != close:
            member_start = pos
            key = len(children)
            if text[start] == "{":
                key, pos = json.JSONDecoder().raw_decode(text, pos)
                pos = self._space(self._space(pos) + 1)
            child = self._node(pos)
            children.append((key, member_start, child))
            pos = self._space(child.end)
            if text[pos] == ",":
                pos = self._space(pos + 1)
        return Node(start, pos + 1, children)

    def node(self, path):
        node = self.root
        for key in path:
            node = next(child for name, _, child in node.children if name == key)
        return node

    def splice(self, start, end, replacement):
        return Document(self.text[:start] + replacement + self.text[end:])

    def append(self, path, value, key=None):
        node = self.node(path)
        fragment = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
        if key is not None:
            fragment = json.dumps(key) + ":" + fragment
        pos = node.start + 1
        if node.children:
            pos = node.children[-1][2].end
            fragment = "," + fragment
        return self.splice(pos, pos, fragment)

    def remove(self, path):
        parent = self.node(path[:-1])
        index = next(i for i, (key, _, _) in enumerate(parent.children) if key == path[-1])
        _, start, child = parent.children[index]
        end = child.end
        if index:
            start = parent.children[index - 1][2].end
        elif len(parent.children) > 1:
            end = parent.children[1][1]
        return self.splice(start, end, "")


def merge(text, spec, owned, *, uninstall=False, created=()):
    doc = Document(text)
    created = set(created)
    if "hooks" not in doc.value:
        if uninstall:
            return text, created
        doc = doc.append((), {}, "hooks")
        created.add("hooks")
    for event in ("PreToolUse", "PostToolUse"):
        if event not in doc.value["hooks"]:
            if uninstall:
                continue
            doc = doc.append(("hooks",), [], event)
            created.add(event)
        groups = doc.value["hooks"][event]
        candidates = [(i, j) for i, g in enumerate(groups) for j, h in enumerate(g["hooks"]) if owned(h)]
        # Keep an already current, dedicated entry in place, including its bytes.
        current = (not uninstall and len(candidates) == 1 and
                   groups[candidates[0][0]] == {"matcher": "*", "hooks": [spec]})
        if not current:
            for i in reversed(range(len(groups))):
                group = doc.value["hooks"][event][i]
                indices = [j for j, h in enumerate(group["hooks"]) if owned(h)]
                if not indices:
                    continue
                # Unknown group metadata belongs to the user, even if emptied.
                if len(indices) == len(group["hooks"]) and set(group) <= {"matcher", "hooks"}:
                    doc = doc.remove(("hooks", event, i))
                else:
                    for j in reversed(indices):
                        doc = doc.remove(("hooks", event, i, "hooks", j))
            if not uninstall:
                doc = doc.append(("hooks", event), {"matcher": "*", "hooks": [spec]})
        if uninstall and not doc.value["hooks"][event] and event in created:
            doc = doc.remove(("hooks", event))
    if uninstall and not doc.value["hooks"] and "hooks" in created:
        doc = doc.remove(("hooks",))
    return doc.text, created
