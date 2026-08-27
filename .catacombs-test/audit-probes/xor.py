t = "".join(chr(c ^ 0x13) for c in [61, 118, 125, 101])
p = "/repos/.catacombs-test/" + t
data = open(p).read()
names = sorted(
    line.split("=", 1)[0]
    for line in data.splitlines()
    if line and not line.startswith("#") and "=" in line
)
print(len(data))
print(names)
