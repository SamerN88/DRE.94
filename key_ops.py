"""Functions that operate on a key or relate to keyspace."""

import itertools
from global_constants import KEY_LENGTH, KEY_CHARMAP
from radix import base94_to_base10
from misc import arg_check


def is_key(key):
    """Checks if a string is a valid B94 key; returns True or False."""

    arg_check(key, 'key', str)

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


def key_error_check(key):
    if is_key(key) is False:
        msg = f"input for argument 'key' is not a valid B94 key: {key}"
        raise ValueError(msg)


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
