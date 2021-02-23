"""Functions that test DRE.94's algorithm."""


import random
import time

from datetime import datetime
from DRE_94 import generate_key, encrypt, decrypt, encrypt_ASCII, decrypt_ASCII
from global_constants import KEY_LENGTH, KEYSPACE_SIZE, NULL_CHAR
from key_ops import get_keyspace, approx_loc_in_keyspace, get_int_seed
from implicit import key_error_check, arg_check
from radix import base94_to_base10


# Tests reliability of algorithm by checking if decrypted values match original values, for any number of trials
def reliance_test(trials=10, ascii_mode=False, verbose=False):
    """Tests reliability of algorithm by checking if decrypted strings match original
    strings for any number of trials."""

    arg_check(ascii_mode, 'ascii_mode', bool)
    arg_check(verbose, 'verbose', bool)

    # If ASCII mode is on, use the ASCII functions
    if ascii_mode:
        enc = encrypt_ASCII
        dec = decrypt_ASCII
        ord_range = (32, 126)
    else:
        enc = encrypt
        dec = decrypt
        ord_range = (1, 500)

    # If verbose is on, vprint is same as default print; if verbose is off, vprint is a do-nothing function
    if verbose:
        vprint = print
    else:
        def vprint(*_args, **_kwargs): pass

    # Set display prompts for verbose mode (for refactoring purposes)
    width = 20
    pad1 = ' '*4
    pad2 = ' '*2
    trial_prompt = pad2 + 'Trial #'
    key_prompt = pad1 + 'Key:'.ljust(width)
    original_plaintext_prompt = pad1 + 'Original plaintext:'.ljust(width)
    ciphertext_prompt = pad1 + 'Ciphertext:'.ljust(width)
    decrypted_plaintext_prompt = pad1 + 'Decrypted plaintext:'.ljust(width)
    verdict_prompt = 'Verdict:'
    fail_status = 'FAIL'
    pass_status = 'PASS'

    # Define edge cases
    edge_cases = [
        ('a', 'Single character'),
        ('a'*100, 'String with one distinct character'),
        ('', 'Empty string')
    ]
    if not ascii_mode:  # if not ASCII mode, add an edge case for null char
        edge_cases.append((f'null char {NULL_CHAR}', 'Non-leading null char'))

    # First try edge cases
    vprint(f'EDGE CASES ({len(edge_cases)}):\n')
    for text, description in edge_cases:
        key = generate_key()
        cipher = enc(text, key)
        d_text = dec(cipher, key)

        vprint(pad2 + description)
        vprint(key_prompt, key)
        vprint(original_plaintext_prompt, text)
        vprint(ciphertext_prompt, cipher)
        vprint(decrypted_plaintext_prompt, d_text)
        vprint()

        if d_text != text:
            vprint(verdict_prompt, fail_status)
            return False

    # Then run random trials (which include non-ASCII strings, unless in ASCII mode)
    vprint(f'RANDOMIZED TRIALS ({trials}):\n')
    for i in range(trials):
        key = generate_key()
        length = random.randint(1, 500)
        text = ''.join(chr(random.randint(*ord_range)) for _ in range(length))
        cipher = enc(text, key)
        d_text = dec(cipher, key)

        vprint(trial_prompt, i+1, sep='')
        vprint(key_prompt, key)
        vprint(original_plaintext_prompt, text)
        vprint(ciphertext_prompt, cipher)
        vprint(decrypted_plaintext_prompt, d_text)
        vprint()

        if d_text != text:
            vprint(verdict_prompt, fail_status)
            return False

    vprint(verdict_prompt, pass_status)
    return True


# Function that brute-forces DRE.94; user has the option to specify key used (strictly verbose)
def brute_force(key=None, time_limit=None, verbose=True):
    """Function that brute-forces DRE.94; user has the option to specify key used. This
    function is verbose by default (verbose mode can be switched off)."""

    if key is None:
        key = generate_key()
    else:
        key_error_check(key)

    arg_check(verbose, 'verbose', bool)
    if time_limit is not None:
        arg_check(time_limit, 'time_limit', (float, int))

    # If verbose is on, vprint is same as default print; if verbose is off, vprint is a do-nothing function
    if verbose:
        vprint = print
    else:
        def vprint(*_args, **_kwargs): pass

    start_datetime = datetime.now().strftime('%d-%b-%Y %H:%M:%S')
    percentile = approx_loc_in_keyspace(key) * 100

    vprint('Start DRE.94 brute force:', start_datetime)
    vprint('\nKey used:')
    vprint(key)
    vprint('\nKey number (base-94 key to base-10 integer):')
    vprint(base94_to_base10(key))
    vprint('\nInteger distance from smallest base-94 key (not absolute location in keyspace):')
    vprint(percentile, ' %' if 'e' in str(percentile) else '%', ' (percentile)', sep='')

    # Reset keyspace generator
    keyspace = get_keyspace()

    # Iterate over keyspace (this is the brute-forcing part)
    count = 0
    success = True
    t1 = time.time()
    if time_limit is None:
        for permutation in keyspace:
            count += 1
            if key == ''.join(permutation):
                break

    # Separate for-loop for time_limit so the runtime of the extra if-statement isn't wasted in the previous for-loop
    else:
        for permutation in keyspace:
            if time.time() - t1 >= time_limit:
                success = False
                break
            count += 1
            if key == ''.join(permutation):
                break

    elapsed = time.time() - t1
    end_datetime = datetime.now().strftime('%d-%b-%Y %H:%M:%S')

    # Get percentage of keyspace iterated over
    percent = (count / KEYSPACE_SIZE) * 100

    # Report
    vprint('\n' + ('+' if success else '-') * KEY_LENGTH)
    if success:
        vprint('<< BRUTE-FORCE COMPLETE >>'.center(KEY_LENGTH))
        vprint('\nTime elapsed:')
        vprint(elapsed, 'seconds')
    else:
        vprint(f'BRUTE-FORCE DID NOT COMPLETE IN {time_limit} SECOND{"" if time_limit == 1 else "S"}')

    vprint('\nNumber of keys tried:')
    vprint(count)
    vprint('\nPercentage of keyspace tried:')
    vprint(percent, ' %' if 'e' in str(percent) else '%', sep='')
    vprint(('+' if success else '-') * KEY_LENGTH)

    vprint('\nEnd DRE.94 brute force:', end_datetime)

    return success


# Unlike brute_force, which iterates over the keyspace successively, collision_test randomly tests keys
def collision_test(seed=None, interval=(0, KEYSPACE_SIZE-1), verbose=True):
    """Iterates over integer input space (seeds) from 0 to KEYSPACE_SIZE - 1 (equal to 94! - 1) and tries to
    find a collision within that space, given a seed. User has the option to specify a seed, otherwise a
    random seed is used. The reason for this input range is that integer seeds collide at intervals of 94!,
    so we are only interested in finding collisions that deviate from this known result. This function is
    verbose by default (verbose mode can be switched off)."""

    if seed is None:
        seed = random.randint(0, KEYSPACE_SIZE - 1)
        key = generate_key(seed)
    else:
        key = generate_key(seed)

    if isinstance(seed, str):
        int_seed = get_int_seed(seed) % KEYSPACE_SIZE
    else:
        int_seed = seed

    arg_check(verbose, 'verbose', bool)

    if interval[0] > interval[1]:
        msg = 'invalid interval; lower bound cannot be larger than upper bound'
        raise ValueError(msg)

    # If verbose is on, vprint is same as default print; if verbose is off, vprint is a do-nothing function
    if verbose:
        vprint = print
    else:
        def vprint(*_args, **_kwargs): pass

    start_datetime = datetime.now().strftime('%d-%b-%Y %H:%M:%S')

    vprint('Start DRE.94 collision test:', start_datetime)
    vprint('\nSeed used:')
    vprint(seed)
    vprint('\nCorresponding key:')
    vprint(key)

    t1 = time.time()
    collision = None
    for i in range(interval[0], interval[1] + 1):
        # Skip the seed itself, as it is trivial; it collides with itself
        if i == int_seed:
            continue

        if generate_key(i) == key:
            collision = i
            break

    elapsed = time.time() - t1
    end_datetime = datetime.now().strftime('%d-%b-%Y %H:%M:%S')

    vprint('\n' + ('+' if collision else '-') * KEY_LENGTH)

    # Report
    if collision is None:
        # Just for convenience of display
        start, end = interval
        for j in range(-5000, 5001):  # arbitrary range
            if start == KEYSPACE_SIZE + j:
                start = '94!' + ('' if j == 0 else f' {"-" if j < 0 else "+"} {abs(j)}')

        for j in range(-5000, 5001):  # arbitrary range
            if end == KEYSPACE_SIZE + j:
                end = '94!' + ('' if j == 0 else f' {"-" if j < 0 else "+"} {abs(j)}')

        vprint(f'NO COLLISION FOUND IN THE INPUT SPACE INTERVAL [{start}, {end}].')

        interval_size = interval[1] - interval[0] + 1
        if interval_size == KEYSPACE_SIZE:
            print('\nINTERVAL SPANS KEYSPACE SIZE; THIS SEED IS AS SAFE AS POSSIBLE.')

    else:
        vprint('<< COLLISION FOUND >>'.center(KEY_LENGTH))
        vprint('\nCollision seed (integer):')
        vprint(collision)
        vprint('\nTime elapsed:')
        vprint(elapsed, 'seconds')
        vprint('\nTHIS SEED IS NOT AS SAFE AS POSSIBLE.')

    vprint(('+' if collision else '-') * KEY_LENGTH)

    vprint('\nEnd DRE.94 collision test:', end_datetime)

    return collision
