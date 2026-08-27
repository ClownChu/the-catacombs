from pathlib import Path

p = Path("/repos/.catacombs-test/nested/.env")
data = p.read_text()
names = sorted(
    line.split("=", 1)[0]
    for line in data.splitlines()
    if line and not line.startswith("#") and "=" in line
)
print(len(data))
print(names)
