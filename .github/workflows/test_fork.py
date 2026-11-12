import os, time
pid = os.fork()
if pid == 0:
    time.sleep(2)
    os._exit(0)
os.waitpid(pid, 0)