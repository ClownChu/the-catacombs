p = "/home/agent/.cursor/hooks/catacombs_guard.py"
d = open(p).read()
print(len(d), "class" in d, "def" in d)
