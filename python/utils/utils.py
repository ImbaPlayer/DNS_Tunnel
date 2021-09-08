import math
import collections

inp_str = input()
counter_char = collections.Counter(inp_str)
print(counter_char)
entropy = 0
for c, ctn in counter_char.items():
    _p = float(ctn)/len(inp_str)
    entropy += -1 * _p * math.log(_p, 2)
print(round(entropy, 7))