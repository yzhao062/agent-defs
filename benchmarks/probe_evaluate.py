"""Reproduce screening and isolated matching probes without hanging the caller."""

import argparse
import json
import subprocess
import sys

from agent_defs.evaluate import screen_pattern


CASES = [
    ("duplicate alternative", r"(a|a)*$", "a" * 30 + "!"),
    ("overlapping alternative", r"(a|aa)+$", "a" * 40 + "!"),
    ("bounded optional repetition positive input", r"^(a?){1,40}a{40}$", "a" * 40),
    ("bounded optional repetition failing suffix", r"^(a?){1,40}a{40}$", "a" * 40 + "!"),
    ("fixed optional repetition", r"^(a?){40}a{40}$", "a" * 40 + "!"),
    ("bounded optional alone", r"^(a?){1,40}$", "a" * 40 + "!"),
    ("bounded optional literal suffix", r"^(a?){1,40}b$", "a" * 40 + "!"),
    ("noncapturing wrapper", r"^((?:a+))+$", "a" * 30 + "!"),
    ("verbose gap", "(?x)(a+) # comment\n +$", "a" * 30 + "!"),
    ("backreference", r"^(a|aa)+\1$", "a" * 40 + "!"),
    ("lookaround with suffix", r"(?=(a|aa)+$).", "a" * 40 + "!"),
    ("unanchored input cost", r"a+b", "a" * 100000 + "!"),
    ("adjacent repetitions", r"^a+a+$", "a" * 100000 + "!"),
    ("lookaround input cost", r"(?=a+b)a", "a" * 100000 + "!"),
    ("adjacent bounded repetitions", r"^a{0,50000}a{0,50000}$", "a" * 100000 + "!"),
    ("character class repetition", r"^([a]+)+$", "a" * 30 + "!"),
    ("bounded nested repetition", r"^(a{1,3}){1,20}$", "a" * 40 + "!"),
    ("EOF lookaround", r"(?=(a|aa)+$)", "a" * 40 + "!"),
    ("first closing class bracket", r"([]+a])+", "]+aaa"),
    ("unquantified group", r"(a+)", "aaa"),
    ("inline flags", r"(?i:a+)", "AAA"),
    ("comment is not regex", "(?x)a # (a+)+\n b", "ab"),
    ("literal open class bracket", r"([[]+)+$", "[" * 30 + "!"),
    ("escaped open bracket", r"(\[+)+$", "[" * 30 + "!"),
    ("escaped backslash", r"(\\+)+$", "\\" * 30 + "!"),
    ("simple backreference", r"(a)\1", "aa"),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=1)
    args = parser.parse_args()
    for name, pattern, payload in CASES:
        try:
            screen_pattern(pattern)
            screening = "accepted"
        except Exception as exc:
            screening = type(exc).__name__ + ": " + str(exc)
        # Pattern and input arrive as JSON on stdin, never as executable source.
        code = '''
import json, re, sys, time
data=json.load(sys.stdin)
pattern=re.compile(data["pattern"], re.IGNORECASE)
print("ready", flush=True)
start=time.perf_counter()
hit=pattern.search(data["payload"])
print(json.dumps({"match":bool(hit), "match_ms":1000*(time.perf_counter()-start)}), flush=True)
'''
        try:
            result = subprocess.run([sys.executable, "-I", "-S", "-c", code],
                                    input=json.dumps(dict(pattern=pattern, payload=payload)).encode(),
                                    capture_output=True, timeout=args.timeout)
            match = result.stdout.decode().strip().splitlines()
        except subprocess.TimeoutExpired as exc:
            match = {"timeout_s": args.timeout, "reached_matching": b"ready" in (exc.output or b"")}
        print(json.dumps(dict(name=name, pattern=pattern, input_chars=len(payload),
                              screening=screening, matching=match)), flush=True)


if __name__ == "__main__":
    main()
