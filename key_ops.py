"""Functions that operate on a key or relate to keyspace."""

import itertools
from global_constants import KEY_LENGTH, KEY_CHARMAP
from radix import base94_to_base10
from implicit import key_error_check


def is_key(key):
    """Checks if a string is a valid B94 key (will not accept any other iterable besides str); returns True or False."""

    # Check that key is of type str (if key is represented as list or tuple, problems occur in encryption/decryption)
    if type(key) != str:
        return False

    # Check for correct key length
    if len(key) != KEY_LENGTH:
        return False

    # Check for character uniqueness
    for ch in key:
        if key.count(ch) != 1:
            return False

    # Check that key uses KEY_CHARMAP characters (ASCII 33 to 126)
    for ch in key:
        if ch not in KEY_CHARMAP:
            return False

    return True


def approx_loc_in_keyspace(key):
    """Returns a value between 0 and 1 (inclusive) indicating approximate location of key in keyspace,
    i.e. the integer distance from the smallest base-94 key (not absolute location in keyspace)."""

    key_error_check(key)

    kmin = base94_to_base10(KEY_CHARMAP)
    kmax = base94_to_base10(KEY_CHARMAP[::-1])

    return (base94_to_base10(key) - kmin) / (kmax - kmin)


# This returns a new generator when called; useful when desire is to reset KEYSPACE generator
def get_keyspace():
    """Returns a Python generator for all possible B94 keys as lists of characters instead of strings."""

    return itertools.permutations(KEY_CHARMAP, KEY_LENGTH)
