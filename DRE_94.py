"""Dynamic Radix Encryption with base-94 cipher (DRE.94): private key text encryption cryptosystem

   Author: Samer N. Najjar (About me: https://najjarcv.imfast.io/)
   Date launched: 18 October 2019
   Last updated: 24 January 2021

   Keyspace size: 94! (~ 1.0873661567e+146)

   Supports arbitrary plaintext character encoding (ciphertext strictly ASCII)."""

# Structure project: https://docs.python-guide.org/writing/structure/

# TODO: TWEAK COLLISION TEST TO FIND SEEDS THAT COLLIDE
# TODO: update docstrings to describe parameters and return values and their types
# TODO: consider how to access all methods from DRE.94 as such (might have to restructure library):
#   [SUBJECT TO CHANGE]
#   DRE_94.<method> for all main cryptographic functionality
#   DRE_94.<module>.<method> for all ancillary functionality (like base-conversion)
# TODO: later make DRE.94 webpage, if deemed useful since Github already exists (useful for CV)
#   [check out https://docs.python-guide.org/writing/structure/]

# TODO: investigate whether base is just required to be the next prime after 1114111 (max Unicode)


import time as _time

from implicit import (
    driver_cwd as _driver_cwd, 
    arg_check as _arg_check, 
    shuffle_base11 as _shuffle_base11, 
    key_error_check as _key_error_check, 
    shuffle as _shuffle
)
from radix import (
    baseN_to_base10 as _baseN_to_base10, 
    base10_to_baseN as _base10_to_baseN,
)
from global_constants import KEY_CHARMAP, KEY_LENGTH, PRINTABLE_ASCII, M512, NULL_CHAR


def hash_seed(seed, size, base=M512):
    if isinstance(seed, int):
        return seed % size
    elif isinstance(seed, str):
        pass
    else:
        msg = f"seed type must be 'int' or 'str', not '{type(seed).__name__}'"
        raise TypeError(msg)

    if size == 1:
        return 0

    hash_idx = 0
    for ch in seed[::-1]:
        code = ord(ch)
        hash_idx = (hash_idx * base + code) % size

    return hash_idx


# Generates a string of length 94 with distinct characters, using ASCII values 33-126
def generate_key(seed=None):
    """Generates a DRE.94 key: string of length 94 with distinct characters, using ASCII characters 33-126."""

    # Default seed is microseconds since epoch
    if seed is None:
        # Ensures at least 1 microsecond between consecutive key generations to ensure that
        # the default seed has changed to avoid generating the same key consecutively
        # (this is mainly an issue for systems with high processing power)
        _time.sleep(1e-6)
        seed = _time.time_ns() // 1000

    charset = list(KEY_CHARMAP)

    # First pass generates intermediate key
    intermediate = []
    for size in range(KEY_LENGTH, 0, -1):
        # Hash the seed to get index in charset
        idx = hash_seed(seed, size)
        ch = charset[idx]

        # Add char to intermediate key, and remove it from charset
        intermediate.append(ch)
        charset.remove(ch)

    # Second pass generates final key, using intermediate key as charset
    # (purpose of 2nd pass is to ensure close seeds do not produce close keys)
    key = []
    for size in range(KEY_LENGTH, 0, -1):
        # Hash the seed to get index in intermediate key
        idx = hash_seed(seed, size)
        ch = intermediate[idx]

        # Add char to final key, and remove it from intermediate key
        key.append(ch)
        intermediate.remove(ch)

    return ''.join(key)


def load_plaintext(text_source, fromfile):
    _arg_check(fromfile, 'fromfile', bool)

    if fromfile:
        # If filename, get text from file
        try:
            text_file = open(_driver_cwd(text_source))
            plaintext = text_file.read()
        except UnicodeDecodeError as e:
            msg = f'{e.args[4]}\n{" " * 20}(could not read text from file: {_driver_cwd(text_source)})'
            raise UnicodeDecodeError(*e.args[:4], msg)

    else:
        # If raw text is passed, use text_source directly as the plaintext
        plaintext = text_source

    return plaintext


def load_ciphertext(text_source, fromfile):
    _arg_check(fromfile, 'fromfile', bool)

    # Determine if cipher source is filename or raw cipher
    if fromfile:
        # If filename, get cipher from text file
        try:
            cipher_file = open(_driver_cwd(text_source), 'r')
            ciphertext = cipher_file.read().replace('\n', '').replace('\t', '').replace(' ', '')  # ignore whitespace
            cipher_file.close()
        except UnicodeDecodeError as e:
            msg = f'{e.args[4]}\n{" " * 20}(could not read text from file: {_driver_cwd(text_source)})'
            raise UnicodeDecodeError(*e.args[:4], msg)

    else:
        ciphertext = text_source

    for ch in ciphertext:
        if ch not in KEY_CHARMAP:
            msg = 'invalid DRE.94 cipher; all characters must be from set of ASCII codes 33 to 126'
            raise ValueError(msg)

    return ciphertext


# Encrypts string with arbitrary character encoding into ASCII ciphertext
def encrypt(text_source, key, fromfile=False):
    """Encrypts string with arbitrary character encoding into ASCII ciphertext (using a DRE.94 key)."""

    _key_error_check(key)

    plaintext = load_plaintext(text_source, fromfile)
    if plaintext == '':
        return ''

    # Ensures plaintext never starts with 0th digit; null character is used as dummy 0th digit in charset.
    # The null character can be encrypted, but it can not be the leading character in plaintext because
    # it is set as the 0th digit for all ciphers, and leading zero digits vanish upon decryption
    if plaintext[0] == NULL_CHAR:
        msg = 'null character (\\x00) forbidden as leading character in plaintext'
        raise ValueError(msg)

    # Get set of distinct chars in plaintext to be used as digits (numbering system)
    # (not using set() b/c it's inconsistent)
    charset = []
    for ch in plaintext:
        if ch not in charset:
            charset.append(ch)

    # Shuffle charset (symbol set) to prevent one-to-one char comparison between
    # ciphers that used different keys but same plaintext
    charset = _shuffle(charset, key)

    # Since the null char is added later as the 0th digit, it must be removed from this charset if present
    if NULL_CHAR in charset:
        charset.remove(NULL_CHAR)

    # Convert plaintext to base-10 integer using charset. Prepend null char to charset because:
    #   - leading zero digits in plaintext vanish upon decryption
    #   - null char is forbidden as leading character in plaintext when encrypting
    #   - hence, initial null char in charset ensures no leading zero digits in plaintext
    base10_cipher_no_tag = _baseN_to_base10(plaintext, [NULL_CHAR] + charset)

    # Tag contains ords of charset (lengthens cipher, but necessary for arbitrary character encoding)
    tag = ' '.join(str(ord(ch)) for ch in charset)  # tag is in base-11 (0123456789 + SPACE)

    # Get shuffled base-11 symbol set with key as seed (shuffled to further obscure cipher)
    base11_symbols = _shuffle_base11(key)

    # Combine base-11 tag and base-10 cipher, get full base-11 cipher; then convert full base-11 cipher to base-10
    base11_cipher = f'{tag} {base10_cipher_no_tag}'
    base10_cipher = _baseN_to_base10(base11_cipher, base11_symbols)

    # Finally, convert full base-10 cipher to base-94 with key
    cipher = _base10_to_baseN(base10_cipher, key)

    return cipher


# Decrypts ASCII ciphertext into plaintext with arbitrary character encoding
def decrypt(cipher_source, key, fromfile=False):
    """Decrypts ASCII ciphertext into plaintext with arbitrary character encoding (using a DRE.94 key)."""

    _key_error_check(key)

    cipher = load_ciphertext(cipher_source, fromfile)
    if cipher == '':
        return ''

    # Convert base-94 cipher to base-10 integer using key
    base10_cipher = _baseN_to_base10(cipher, key)

    # Get shuffled base-11 symbol set with key as seed
    base11_symbols = _shuffle_base11(key)

    # Convert base-10 cipher to base-11 cipher to get the tag and message portions of the cipher
    base11_cipher = _base10_to_baseN(base10_cipher, base11_symbols)

    # Separate tag and message portions of the cipher
    base11_cipher_split = base11_cipher.split()
    tag_list = base11_cipher_split[:-1]
    base10_cipher_no_tag = int(base11_cipher_split[-1])

    # From tag, get ords of plaintext charset, then build charset with ords
    ords = map(int, tag_list)
    charset = [chr(i) for i in ords]

    # Get plaintext (base-N text) using charset which was derived earlier
    plaintext = _base10_to_baseN(base10_cipher_no_tag, [NULL_CHAR] + charset)

    return plaintext


# Encrypts string with ASCII character encoding into ASCII ciphertext
def encrypt_ASCII(text_source, key, fromfile=False):
    """Encrypts ASCII string into ASCII ciphertext (using a DRE.94 key)."""

    _key_error_check(key)

    plaintext = load_plaintext(text_source, fromfile)
    if plaintext == '':
        return ''

    # Ensures plaintext is printable ASCII
    for ch in plaintext:
        if ch not in PRINTABLE_ASCII:
            msg = 'plaintext characters must be printable ASCII (codes 9-13, 32-126)'
            raise ValueError(msg)

    # Shuffle ASCII symbol set to prevent one-to-one char comparison between
    # ciphers that used different keys but same plaintext
    shuffled_ascii = _shuffle(PRINTABLE_ASCII, key)

    # Convert plaintext to base-10 integer using charset. Prepend null char to charset because:
    #   - leading zero digits in plaintext vanish upon decryption
    #   - null char is forbidden in plaintext when encrypting
    #   - hence, initial null char in charset ensures no leading zero digits in plaintext
    base10_cipher = _baseN_to_base10(plaintext, [NULL_CHAR] + shuffled_ascii)

    # Finally, convert base-10 cipher to base-94 with key
    cipher = _base10_to_baseN(base10_cipher, key)

    return cipher


def decrypt_ASCII(cipher_source, key, fromfile=False):
    """Decrypts ASCII ciphertext into ASCII plaintext (using a DRE.94 key)."""

    _key_error_check(key)

    cipher = load_ciphertext(cipher_source, fromfile)
    if cipher == '':
        return ''

    # Convert base-94 cipher to base-10 integer using key
    base10_cipher = _baseN_to_base10(cipher, key)

    # Get shuffled ASCII symbol set
    shuffled_ascii = _shuffle(PRINTABLE_ASCII, key)

    # Get plaintext (base-100 text) using shuffled ASCII charset
    plaintext = _base10_to_baseN(base10_cipher, [NULL_CHAR] + shuffled_ascii)

    return plaintext
