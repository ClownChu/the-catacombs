for name in ("guard_obfuscation.py", "guard_shell.py"):
    p = "/home/agent/.cursor/hooks/" + name
    d = open(p).read()
    print(name, len(d), "class" in d, "def" in d)
