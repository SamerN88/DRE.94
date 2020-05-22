"""Global constants, fundamental values of B94."""

import itertools
from misc import permute

# Ordered string to be shuffled to generate key
KEY_CHARMAP = ''.join(chr(i) for i in range(33, 126+1))

ASCII = [chr(i) for i in range(0, 127+1)]

KEY_LENGTH = 94
KEYSPACE_SIZE = permute(len(KEY_CHARMAP), KEY_LENGTH)

# Generator containing all possible keys as lists (created upon importing module)
KEYSPACE = itertools.permutations(KEY_CHARMAP, KEY_LENGTH)
