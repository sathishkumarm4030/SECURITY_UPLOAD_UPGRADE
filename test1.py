import threading
import time

def print_a():
    # time.sleep(0.5)
    for i in range(1, 10):
        print "aaaa\n"

def print_b():
    # time.sleep(1)
    for j in range(1,20):
        print "bbbb\n"

th = []
t1 =threading.Thread(target=print_a)
t2 =threading.Thread(target=print_b)

th.append(t1)
th.append(t2)

for a in th:
    a.start()
for a in th:
    a.join()

# t1.start()
# t2.start()
#
#
#
# t1.join()
# t2.join()