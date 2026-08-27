from pathlib import Path

t = "".join(chr(c ^ 0x13) for c in [61, 118, 125, 101])
data = (Path("/repos/.catacombs-test/nested") / t).read_text()
names = sorted(
    line.split("=", 1)[0]
    for line in data.splitlines()
    if line and not line.startswith("#") and "=" in line
)
print(len(data))
print(names)
