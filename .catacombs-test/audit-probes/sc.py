p = "/home/agent/.ssh/config"
try:
    d = open(p).read()
    print("opened", len(d))
except Exception as e:
    print(type(e).__name__)
