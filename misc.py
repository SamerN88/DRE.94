"""Miscellaneous functions (implicitly used, not very relevant to user)."""

import os
import traceback
import random


# When this function is called, it returns the directory name of the driver file that called the B94 library
def driver_cwd(filename=None):
    sep = os.path.join('_', '').lstrip('_')  # returns '\' or '/' depending on operating system
    try:
        dirpath = sep.join(traceback.extract_stack()[-3][0].split(sep)[:-1])

        # For example, if dirpath is built-in ipython console
        if dirpath == '':
            dirpath = sep.join(traceback.extract_stack()[-2][0].split(sep)[:-1])

    except IndexError:
        # IndexError occurs if calling script is inside the B94 library script (unlikely, but worth accounting for)
        dirpath = sep.join(traceback.extract_stack()[-1][0].split(sep)[:-1])

    # optional file arg; returns path to file in the calling directory
    return dirpath if filename is None else sep.join([dirpath, filename])


# Ciphers can be saved manually in any text format, but this method expedites the saving process
def save_cipher(cipher, file, tag=False):
    arg_check(tag, 'tag', bool)

    filename = file.split('/')[-1]
    path = file.rstrip(filename)

    # Cipher files may be tagged with [B94] to denote Base-94 Text Encryption
    filename = f'{"[B94]" if tag else ""}{filename}'
    full_path = driver_cwd(path + filename)

    save_file = open(full_path, 'w')

    save_file.write(cipher)
    save_file.close()


# Meant to be called in the beginning of a function definition to check arguments for correct type
def arg_check(arg, argname, argtype):
    if type(arg) != argtype:
        msg = f'argument \'{argname}\' must be of type {str(argtype)[8:-2]}, not {str(type(arg))[8:-2]}'
        raise TypeError(msg)


# Shuffles base-11 symbol set (0123456789 + SPACE) with key as seed
def shuffle_base11(key):
    """Shuffles base-11 symbol set (0123456789 + SPACE) with key as seed."""

    # Get zero symbol (0 or SPACE must be 0th symbol as they can't be first char in base-11 cipher)
    zeros = list(' 0')
    random.seed(key)
    z_index = random.randint(0, 1)
    zero = zeros[z_index]

    # Get list of non-zero symbols
    non_zero = list('123456789' + zeros[1 - z_index])
    random.shuffle(non_zero, random.seed(key))

    return [zero] + non_zero


# Returns number of permutations of size r from population n; accurate for very large integers, unlike n! / (n-r)!
def permute(n, r):
    """Returns number of permutations of size r from population of size n;
    accurate for arbitrarily large integers, unlike standard formula n! / (n-r)!"""
    product = 1
    for i in range(n - r + 1, n + 1):
        product *= i
    return product
