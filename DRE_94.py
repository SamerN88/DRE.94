"""Dynamic Radix Encryption with base-94 cipher (DRE.94): private key text encryption cryptosystem

   Author: Samer N. Najjar (About me: https://najjarcv.imfast.io/)
   Date launched: 18 October 2019
   Last updated: 4 June 2020

   Keyspace size: 94! (~ 1.0873661567e+146)

   Supports arbitrary plaintext character encoding (ciphertext strictly ASCII)."""

# TODO: TWEAK COLLISION TEST TO FIND SEEDS THAT COLLIDE?
# TODO: FIX ENCRYPTION SO IT CAN ENCRYPTION SINGLE-LENGTH CHARSET LIKE 's' OR 'ssss'

# TODO: remove obstructor and instead use this method to prevent cipher comparison:
#    TODO: don't use set() to get charset, use for-loop to get distinct chars then shuffle list with key as seed
#    TODO: OR FIND WAY TO PREDICT LENGTH OF BASE-10 CIPHER AND MAKE OBSTRUCTOR WITHIN 1 DIGIT SAME LENGTH
# TODO: change order of base-11 cipher elements: cipher first, then tag
# TODO: update docstrings to describe parameters and return values and their types
# TODO: consider how to access all methods from DRE_94.<method>; might have to restructure library

import random
import secrets

from implicit import driver_cwd, arg_check, shuffle_base11, key_error_check, get_obstructor
from radix import baseN_to_base10, base10_to_baseN
from global_constants import KEY_CHARMAP, KEY_LENGTH


# Generates a string of length 94 with distinct characters, using ASCII values 33-126
def generate_key(seed=None):
    """Generates a DRE.94 key: string of length 94 with distinct characters, using ASCII characters 33-126."""

    # If seed, ensure that seed is hashable; if not, raise proper error plus the invalid seed
    if seed is not None:
        try:
            random.seed(seed)
            key = ''.join(random.sample(KEY_CHARMAP, KEY_LENGTH))

        except TypeError as e:
            msg = f'{e.args[0]}\n{" "*11}invalid seed: {seed}'
            e.args = (msg,)
            raise

    # If no seed, use secrets library instead of random.sample() to generate key more securely
    else:
        kmap = list(KEY_CHARMAP)
        key = ''
        for i in range(KEY_LENGTH):
            char = secrets.choice(kmap)
            key += char
            kmap.remove(char)

    return key


# Encrypts string with arbitrary character encoding into ASCII ciphertext
def encrypt(text_source, key, fromfile=False):
    """Encrypts string with arbitrary character encoding into ASCII ciphertext (using a DRE.94 key)."""

    arg_check(fromfile, 'fromfile', bool)
    key_error_check(key)

    if fromfile:
        # If filename, get text from file
        try:
            text_file = open(driver_cwd(text_source))
            text = text_file.read()
        except UnicodeDecodeError as e:
            msg = f'{e.args[4]}\n{" " * 20}(could not read text from file: {driver_cwd(text_source)})'
            raise UnicodeDecodeError(*e.args[:4], msg)

    else:
        # If raw text is passed, use text_source directly as the text
        text = text_source

    # Ensures text never starts with 0th digit; null character is used as dummy 0th digit in charset
    if '\0' in text:
        msg = 'null character (\\x00) forbidden in plaintext'
        raise ValueError(msg)

    if text == '':
        return ''

    # Get set of distinct chars in text to be used as numbering system (not using set() b/c it's inconsistent)
    charset = []
    for ch in text:
        if ch not in charset:
            charset.append(ch)
    random.seed(key)
    random.shuffle(charset)

    # Convert text to base-10 integer using charset
    base10_cipher = baseN_to_base10(text, ['\0'] + charset)  # initial null character ensures no zero digit in text

    # Get shuffled base-11 symbol set with key as seed
    base11_symbols = shuffle_base11(key)

    # Tag contains info on length of text and ords of charset (lengthens cipher, but necessary for arbitrary charset)
    tag = ' '.join(str(ord(ch)) for ch in charset)  # tag is in base-11 (0123456789 + SPACE)

    # Combine base-11 tag and base-10 cipher, get full base-11 cipher; then convert full base-11 cipher to base-10
    base11_cipher = tag + ' ' + str(base10_cipher)
    base10_cipher_with_tag = baseN_to_base10(base11_cipher, base11_symbols)

    # Finally, convert full base-10 cipher to base-94 with key
    cipher = base10_to_baseN(base10_cipher_with_tag, key)

    return cipher


# Decrypts ASCII ciphertext into plaintext with arbitrary character encoding
def decrypt(cipher_source, key, fromfile=False):
    """Decrypts ASCII ciphertext into plaintext with arbitrary character encoding (using a DRE.94 key)."""

    arg_check(fromfile, 'fromfile', bool)
    key_error_check(key)

    # Determine if cipher source is filename or raw cipher
    if fromfile:
        # If filename, get cipher from text file
        try:
            cipher_file = open(driver_cwd(cipher_source), 'r')
            cipher = cipher_file.read().replace('\n', '').replace(' ', '')  # ignore whitespace
            cipher_file.close()
        except UnicodeDecodeError as e:
            msg = f'{e.args[4]}\n{" " * 20}(could not read text from file: {driver_cwd(cipher_source)})'
            raise UnicodeDecodeError(*e.args[:4], msg)

    else:
        cipher = cipher_source

    for ch in cipher:
        if ch not in KEY_CHARMAP:
            msg = 'invalid DRE.94 cipher; all characters must be from set of ASCII codes 33 to 126'
            raise ValueError(msg)

    if cipher == '':
        return ''

    # Get shuffled base-11 symbol set with key as seed
    base11_symbols = shuffle_base11(key)

    # Convert base-94 cipher to base-10 integer using key
    base10_cipher_with_tag = baseN_to_base10(cipher, key)

    # Convert base-10 cipher to base-11 cipher, i.e. tag and text cipher (also reverse XOR with obstructor)
    base11_cipher = base10_to_baseN(base10_cipher_with_tag, base11_symbols)

    # Separate tag and base-10 cipher
    base11_cipher_split = base11_cipher.split()
    tag_list = base11_cipher_split[:-1]
    base10_cipher = int(base11_cipher_split[-1])

    # From tag, get ords of text charset, then build charset with ords
    ords = [int(i) for i in tag_list]
    charset = [chr(i) for i in ords]

    # Get text (base-N text) using charset which was derived earlier
    text = base10_to_baseN(base10_cipher, ['\0'] + charset)

    return text
