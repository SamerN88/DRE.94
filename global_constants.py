"""Global constants and fundamental values of DRE.94."""

import itertools
import math

# Ordered string to be shuffled to generate key
KEY_CHARMAP = ''.join(chr(i) for i in range(33, 126+1))

ASCII = [chr(i) for i in range(0, 127+1)]

KEY_LENGTH = 94
KEYSPACE_SIZE = math.factorial(KEY_LENGTH)  # if key length not equal to length of KEY_CHARMAP, must use permute(n,r)

# Generator containing all possible keys as lists (created upon importing module)
KEYSPACE = itertools.permutations(KEY_CHARMAP, KEY_LENGTH)
