from os import environ

keys = list(environ.keys())
print(len(keys))
print([k for k in keys if any(x in k.upper() for x in ("PASSWORD", "SECRET", "TOKEN", "API_KEY", "DATABASE"))])
