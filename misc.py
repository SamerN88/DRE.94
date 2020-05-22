"""Miscellaneous functions"""

import traceback


# When this function is called, it returns the directory name of the driver file that called the B94 library
def driver_cwd(filename=None):
    try:
        dirpath = '/'.join(traceback.extract_stack()[-3][0].split('/')[:-1])

        # For example, if dirpath is built-in ipython console
        if dirpath == '':
            dirpath = '/'.join(traceback.extract_stack()[-2][0].split('/')[:-1])

    except IndexError:
        # IndexError occurs if calling script is inside the B94 library script (unlikely, but worth accounting for)
        dirpath = '/'.join(traceback.extract_stack()[-1][0].split('/')[:-1])

    # optional file arg; returns path to file in the calling directory
    return dirpath if filename is None else dirpath + '/' + filename


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


# Can be called in the beginning of a function to check arguments for correct type
def arg_check(arg, argname, argtype):
    if type(arg) != argtype:
        msg = f'argument \'{argname}\' must be of type {str(argtype)[8:-2]}, not {str(type(arg))[8:-2]}'
        raise TypeError(msg)


# Returns number of permutations of size r from population n; accurate for very large integers, unlike n! / (n-r)!
def permute(n, r):
    product = 1
    for i in range(n - r + 1, n + 1):
        product *= i
    return product
