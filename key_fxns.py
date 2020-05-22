"""Functions that operate on a key or relate to keyspace"""

import itertools
from global_constants import KEY_LENGTH, KEY_CHARMAP
from radix import base94_to_base10
from misc import arg_check


def is_key(key):
    arg_check(key, 'key', str)

    # Check for correct key length
    if len(key) != KEY_LENGTH:
        return False

    # Check for character uniqueness
    for ch in key:
        if key.count(ch) != 1:
            return False

    # Check that key uses KEY_CHARMAP characters
    for ch in key:
        if ch not in KEY_CHARMAP:
            return False

    return True


def key_error_check(key):
    if is_key(key) is False:
        msg = "input for argument 'key' is not a valid B94 key"
        raise ValueError(msg)


def approx_loc_in_keyspace(key):
    key_error_check(key)

    kmin = base94_to_base10(KEY_CHARMAP)
    kmax = base94_to_base10(KEY_CHARMAP[:-KEY_LENGTH-1:-1])

    return (base94_to_base10(key) - kmin) / (kmax - kmin)


# This returns a new generator when called; useful when desire is to reset KEYSPACE generator
def get_keyspace():
    return itertools.permutations(KEY_CHARMAP, KEY_LENGTH)
