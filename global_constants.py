"""Global constants and fundamental values of DRE.94."""

import itertools
import math

# Ordered string to be shuffled to generate key
KEY_CHARSET = ''.join(chr(i) for i in range(33, 126 + 1))

PRINTABLE_ASCII = ''.join(chr(i) for i in list(range(9, 13+1)) + list(range(32, 126+1)))

KEY_LENGTH = 94
KEYSPACE_SIZE = math.factorial(KEY_LENGTH)  # if key length not equal to length of KEY_CHARMAP, must use permute(n,r)

# Generator containing all possible keys as lists (created upon importing module)
KEYSPACE = itertools.permutations(KEY_CHARSET, KEY_LENGTH)

# Large Mersenne prime used as a base in the seed hashing function
M512 = 2**512 - 1

# Null char takes the place of the 0th digit during encryption to ensure no leading zeros digits in plaintext
# (leading zeros in plaintext vanish upon decryption)
NULL_CHAR = '\0'
