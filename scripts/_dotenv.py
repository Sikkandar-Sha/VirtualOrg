"""Read .env the way docker compose does, for the Python tools that run on the host.

One parser, imported by scripts/score and scripts/verify.py. Two copies had drifted
from each other and from scripts/_dotenv.sh: they split on any `#` (so a value like
`p#ssw0rd` was truncated), kept surrounding quotes (so `VO_CC_PORT="3200"` built the
URL `http://127.0.0.1:"3200"`), and disagreed about indented keys. The rules below
match the shell loader exactly.

An exported variable always wins.
"""
import os
import re

_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def dotenv(name, default="", path=None):
    if os.environ.get(name):
        return os.environ[name]
    path = path or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env")
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                if not _KEY.match(k) or k != name:
                    continue
                # strip an inline comment only when whitespace precedes the `#`,
                # so `p#ssw0rd` survives
                v = re.split(r"\s+#", v, maxsplit=1)[0].strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                    v = v[1:-1]
                return v or default
    except OSError:
        pass
    return default
