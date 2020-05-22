"""Functions that test B94's algorithm"""


import random
import time

from datetime import datetime
from B94 import generate_key, encrypt, decrypt
from global_constants import KEY_LENGTH, KEYSPACE_SIZE
from key_fxns import get_keyspace, approx_loc_in_keyspace, key_error_check
from radix import base94_to_base10


# Tests reliability of algorithm by checking if decrypted values match original values, for any number of trials
def reliance_test(trials, verbose=True, super_verbose=False):
    if super_verbose:
        verbose = True

    # First try edge cases
    for text in ['a', 'a'*100, '']:
        key = generate_key()
        cipher = encrypt(text, key)
        dtext = decrypt(cipher, key)
        if dtext != text:
            if verbose:
                print('FAIL')
            return False

        if super_verbose:
            print('Key:', key)
            print('Text:', text)
            print('Cipher:', cipher)
            print()

    # Then run random trials (which include non-ASCII values)
    for i in range(trials):
        key = generate_key()
        length = random.randint(0, 500)
        text = ''.join(chr(random.randint(0, 500)) for i in range(length))
        cipher = encrypt(text, key)
        dtext = decrypt(cipher, key)
        if dtext != text:
            if verbose:
                print('FAIL')
            return False

        if super_verbose:
            print('Key:', key)
            print('Text:', text)
            print('Cipher:', cipher)
            print()

    if verbose:
        print('PASS')
    return True


# Function that brute-forces B94; user has the option to specify key used (strictly verbose)
def brute_force(key=None):
    if key:
        key_error_check(key)
    else:
        key = generate_key()

    start_datetime = datetime.now().strftime('%d-%b-%Y %H:%M:%S')
    percentile = approx_loc_in_keyspace(key) * 100

    print('Start brute force:', start_datetime)
    print('\nKey used:')
    print(key)
    print('\nKey number (base-94 key to base-10 integer):')
    print(base94_to_base10(key))
    print('\nInteger distance from smallest base-94 key (not absolute location in keyspace):')
    print(percentile, ' %' if 'e' in str(percentile) else '%', ' (percentile)', sep='')

    # Reset keyspace generator
    keyspace = get_keyspace()

    # Iterate over keyspace (this is the brute-forcing part)
    count = 0
    t1 = time.time()
    for permutation in keyspace:
        count += 1
        if key == ''.join(permutation):
            break

    elapsed = time.time() - t1
    end_datetime = datetime.now().strftime('%d-%b-%Y %H:%M:%S')

    # Get percentage of keyspace iterated over
    percent = (count / KEYSPACE_SIZE) * 100

    # If the printed count is too long, convert to scientific notation
    if len(str(count)) > KEY_LENGTH:
        count = '{:.10e}'.format(count)

    # Report
    print('\n' + '*' * KEY_LENGTH)
    print('<< B94 BRUTE-FORCE COMPLETE >>'.center(KEY_LENGTH))
    print('\nTime elapsed:')
    print(elapsed, 'seconds')
    print('\nNumber of keys tried:')
    print(count)
    print('\nPercentage of keyspace tried:')
    print(percent, ' %' if 'e' in str(percent) else '%', sep='')
    print('*' * KEY_LENGTH)

    print('\nEnd brute force:', end_datetime)


# Method documentation
reliance_test.__doc__ = "Tests reliability of algorithm by checking if decrypted values match original values, " \
                        "for any number of trials"
brute_force.__doc__ = "Function that brute-forces B94; user has the option to specify key used (strictly verbose)"
