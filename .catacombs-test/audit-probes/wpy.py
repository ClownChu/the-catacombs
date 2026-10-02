from pathlib import Path

Path("/var/tmp/catacombs-audit-wpy.txt").write_text("x")
print("wrote")
