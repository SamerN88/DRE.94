"""Functions that are implicitly called by other modules; not intended for direct use by users."""


import os
import traceback

from global_constants import KEY_LENGTH, KEY_CHARMAP
from radix import base94_to_base10


# When this function is called, it returns the directory name of the driver file that called the DRE.94 library
def driver_cwd(filename=None):
    """Returns the path to the directory containing the driver code that initially called the module."""

    sep = os.path.join('_', '').lstrip('_')  # returns '\' or '/' depending on operating system
    try:
        dirpath = sep.join(traceback.extract_stack()[-3][0].split(sep)[:-1])

        # For example, if dirpath is built-in ipython console
        if dirpath == '':
            dirpath = sep.join(traceback.extract_stack()[-2][0].split(sep)[:-1])

    except IndexError:
        # IndexError occurs if calling script is inside the DRE.94 library script (unlikely, but worth accounting for)
        dirpath = sep.join(traceback.extract_stack()[-1][0].split(sep)[:-1])

    # optional file arg; returns path to file in the calling directory
    return dirpath if filename is None else sep.join([dirpath, filename])


# Meant to be called in the beginning of a function definition to check arguments for correct type
def arg_check(arg, argname, argtypes):
    """Checks if passed argument 'arg' is one of the correct types in 'argtypes'."""

    if type(argtypes) == type:
        argtypes = [argtypes]

    type_names = [typ.__name__ for typ in argtypes]

    if type(arg) not in argtypes:
        msg = f'argument \'{argname}\' must be of type {" or ".join(type_names)}, not {type(arg).__name__}'
        raise TypeError(msg)


def shuffle(seq, key):
    seq = list(seq)
    max_len = len(seq)

    key_num = base94_to_base10(key)

    # It is practically impossible that this function will receive a sequence longer than key_num ONLY
    # IF key is actually a DRE.94 key, as key_num would be on the order of 10**181 or more; but it is
    # worth coding for this in the event that key is something else that would produce a small key_num
    while key_num < max_len:
        key_num *= key_num

    shuffled = []
    for size in range(max_len, 0, -1):
        item = seq[key_num % size]
        shuffled.append(item)
        seq.remove(item)

    return shuffled


# Shuffles base-11 symbol set (0123456789 + SPACE) with key as seed
def shuffle_base11(key):
    """Shuffles base-11 symbol set (0123456789 + SPACE) with DRE.94 key as seed."""

    key_error_check(key)

    key_num = base94_to_base10(key)
    zeros = (' ', '0')
    zero = zeros[key_num % 2]

    non_zero = list('123456789' + zeros[1 - (key_num % 2)])
    symbol_set = shuffle(non_zero, key)

    return [zero] + symbol_set


def key_error_check(key):
    """Checks if argument 'key' is a valid DRE.94 key, and raises error with specific reason if not."""

    msg = "input for argument 'key' is not a valid DRE.94 key (reason: {})"

    # Check that key is of type str (if key is represented as list or tuple, problems occur in encryption/decryption)
    if type(key) != str:
        raise TypeError(msg.format("DRE.94 key must be represented as a string (type str)"))

    # Check for correct key length
    if len(key) != KEY_LENGTH:
        raise ValueError(msg.format(f"DRE.94 key must be of length {KEY_LENGTH}"))

    # Check for character uniqueness
    for ch in key:
        if key.count(ch) != 1:
            raise ValueError(msg.format(f"DRE.94 key must contain only distinct characters"))

    # Check that key uses KEY_CHARMAP characters (ASCII 33 to 126)
    for ch in key:
        if ch not in KEY_CHARMAP:
            raise ValueError(msg.format(f"DRE.94 key must contain only ASCII characters 33 to 126, inclusive"))
