"""Functions that operate on a key or relate to keyspace."""

import itertools
from global_constants import KEY_LENGTH, KEY_CHARSET, M512
from radix import base94_to_base10
from implicit import key_error_check


def is_key(key):
    """Checks if a string is a valid DRE.94 key (will not accept any other iterable besides str); returns True or False."""

    # Check that key is of type str (if key is represented as list or tuple, problems occur in encryption/decryption)
    if type(key) != str:
        return False

    # Check for correct key length
    if len(key) != KEY_LENGTH:
        return False

    # Check that key uses all KEY_CHARSET characters (ASCII 33 to 126)
    for ch in KEY_CHARSET:
        if ch not in key:
            return False

    return True


def approx_loc_in_keyspace(key):
    """Returns a value between 0 and 1 (inclusive) indicating approximate location of key in keyspace,
    i.e. the integer distance from the smallest base-94 key over the integer distance between the smallest
    and largest keys (not absolute location in keyspace)."""

    key_error_check(key)

    kmin = base94_to_base10(KEY_CHARSET)
    kmax = base94_to_base10(KEY_CHARSET[::-1])

    return (base94_to_base10(key) - kmin) / (kmax - kmin)


# This returns a new generator when called; useful when desire is to reset KEYSPACE generator
def get_keyspace():
    """Returns a Python generator for all possible DRE.94 keys as lists of characters instead of strings."""

    return itertools.permutations(KEY_CHARSET, KEY_LENGTH)


# Converts a string seed into its integer counterpart; the string seed and the integer seed cause a collision
def get_int_seed(str_seed):
    return sum(ord(ch) * (M512**i) for i, ch in enumerate(str_seed))
