"""Global constants and fundamental values of DRE.94."""

import itertools
import math

# Ordered string to be shuffled to generate key
KEY_CHARMAP = ''.join(chr(i) for i in range(33, 126+1))

PRINTABLE_ASCII = tuple(chr(i) for i in list(range(9, 13+1)) + list(range(32, 126+1)))  # printable ASCII chars

KEY_LENGTH = 94
KEYSPACE_SIZE = math.factorial(KEY_LENGTH)  # if key length not equal to length of KEY_CHARMAP, must use permute(n,r)

# Generator containing all possible keys as lists (created upon importing module)
KEYSPACE = itertools.permutations(KEY_CHARMAP, KEY_LENGTH)
