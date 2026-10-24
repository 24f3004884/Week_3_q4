import hashlib
import json
import secrets
import time


def normalize(o):
    if isinstance(o, float) and o.is_integer():
        return int(o)
    if isinstance(o, dict):
        return {k: normalize(v) for k, v in o.items()}
    if isinstance(o, list):
        return [normalize(v) for v in o]
    return o


def canon(o):
    return json.dumps(normalize(o), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def digest_args(args):
    return sha256_hex(canon(args))


def now_ns():
    return time.time_ns()


def new_hex(nbytes):
    while True:
        v = secrets.token_hex(nbytes)
        if set(v) != {"0"}:
            return v


def new_id(prefix):
    return f"{prefix}_{secrets.token_hex(8)}"


def dumps(o):
    return json.dumps(o, ensure_ascii=False, separators=(",", ":"))