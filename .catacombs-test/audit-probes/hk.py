p = "/home/agent/.cursor/hooks.json"
d = open(p).read()
print(len(d), "hooks" in d, "command" in d)
