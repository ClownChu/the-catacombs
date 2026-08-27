p = "/home/agent/.cursor/catacombs-security.json"
d = open(p).read()
print(len(d))
print("medium" in d, '"id"' in d)
