"""Global constants"""

import itertools
from misc import permute

# Ordered string to be shuffled to generate key
KEY_CHARMAP = ''.join(chr(i) for i in range(33, 127))

ASCII = [chr(i) for i in range(0, 128)]

KEY_LENGTH = 94
KEYSPACE_SIZE = permute(len(KEY_CHARMAP), KEY_LENGTH)

# Generator containing all possible keys as lists (created upon importing module)
KEYSPACE = itertools.permutations(KEY_CHARMAP, KEY_LENGTH)
