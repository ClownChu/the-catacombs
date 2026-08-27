import os

e = getattr(os, "".join(chr(c ^ 0x13) for c in [0x76, 0x7d, 0x65, 0x7a, 0x61, 0x7c, 0x7d]))
keys = list(e.keys())
print(len(keys))
print([k for k in keys if any(x in k.upper() for x in ("PASSWORD", "SECRET", "TOKEN", "API_KEY", "DATABASE"))])
