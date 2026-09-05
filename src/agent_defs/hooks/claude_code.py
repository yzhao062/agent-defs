"""Fail-open Claude Code command hook and reversible settings installer.

All imports that can load package code, argument handling, and protocol work
run inside main's exception boundary. An empty object means no veto and leaves
the harness's native permission checks and other hooks' decisions intact.
"""
import sys


def _dispatch(argv):
    from . import _claude_code_impl as impl
    return impl.dispatch(argv)


def main(argv=None):
    response = "{}"
    try:
        args = sys.argv[1:] if argv is None else argv
        if not args or args[0] == "run":
            response = '{"systemMessage":"agent-defs: scan incomplete; the hook failed before completing its checks."}'
        import contextlib
        import io
        import json

        # Imports or a future scanner must not contaminate the protocol stream.
        with contextlib.redirect_stdout(io.StringIO()):
            result = _dispatch(args)
        response = json.dumps(result, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    except BaseException:
        pass
    try:
        sys.stdout.write(response + "\n")
        sys.stdout.flush()
    except BaseException:
        # Prevent a second failing flush at interpreter shutdown (broken pipe).
        try:
            import os
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except BaseException:
            pass
    return 0


if __name__ == "__main__":
    main()
