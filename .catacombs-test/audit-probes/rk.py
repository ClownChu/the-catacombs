p = "/home/agent/.ssh/id_rsa"
try:
    d = open(p).read()
    print("opened", len(d))
except Exception as e:
    print(type(e).__name__)
