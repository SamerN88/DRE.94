"""BASE-94 ENCRYPTION (B94): Private key text encryption algorithm

   Author: Samer N. Najjar
   Date launched: 18 October 2019
   Last updated: 21 May 2020

   Keyspace size ~ 1.0873661567e+146

   Supports arbitrary input character encoding (output ciphertext strictly ASCII)"""

# TODO: consider how to access all methods from B94.<method> (possibly have central file that imports * from all files)

import random
import secrets

from misc import driver_cwd, arg_check
from radix import baseN_to_base10, base10_to_baseN
from global_constants import KEY_CHARMAP, KEY_LENGTH
from key_fxns import key_error_check


# Generates a string of length 94 with unique characters, using ASCII values 33-126
def generate_key(seed=None):
    # If seed, ensure that seed is hashable; if not, raise proper error plus the invalid seed
    if seed:
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
    arg_check(fromfile, 'fromfile', bool)
    key_error_check(key)

    if fromfile:
        # If filename, get text from file
        text_file = open(driver_cwd(text_source))
        text = ''.join(text_file.readlines())

    else:
        # If raw text is passed, use text_source directly as the text
        text = text_source

    if text == '':
        return ''

    # Get set of unique chars in text; to be used as numbering system.
    charset = list(set(text))

    # If first character in text is 0th digit, it will disappear in decryption; swap first and last digits to fix this
    if text[0] == charset[0]:
        zero = charset[0]
        charset[0] = charset[-1]
        charset[-1] = zero

    # Cipher is XOR'd with obstructor so equivalent ciphers with different keys can't be compared for 1:1 matching chars
    obstructor = abs(hash(key))

    # Convert text to base-10 integer using charset (then obstruct)
    base10_cipher = baseN_to_base10(text, charset) ^ obstructor

    # Get shuffled base-11 digits with key as seed
    base11_digits = get_base11_digits(key)

    # Tag contains info on length of text and ords of charset (lengthens cipher, but necessary for arbitrary charset)
    tag = str(len(text)) + ' ' + ' '.join(str(ord(ch)) for ch in charset)  # tag is in base-11 (0123456789 + SPACE)

    # Combine base-11 tag and base-10 cipher, get full base-11 cipher; then convert full base-11 cipher to base-10
    base11_cipher = tag + ' ' + str(base10_cipher)
    base10_cipher_with_tag = baseN_to_base10(base11_cipher, base11_digits) ^ obstructor  # then obstruct once more

    # Finally, convert full base-10 cipher to base-94 with key
    cipher = base10_to_baseN(base10_cipher_with_tag, key)

    return cipher


# Decrypts ASCII ciphertext into plaintext with arbitrary character encoding
def decrypt(cipher_source, key, fromfile=False):
    arg_check(fromfile, 'fromfile', bool)
    key_error_check(key)

    # Determine if cipher source is filename or raw cipher
    if fromfile:
        # If filename, get cipher from text file
        try:
            cipher_file = open(driver_cwd(cipher_source), 'r')
            cipher = cipher_file.readlines()[0]
            cipher_file.close()
        except UnicodeDecodeError as e:
            msg = f'{e.args[4]}\n{" " * 20}(could not read file as ciphertext: {driver_cwd(cipher_source)})'
            raise UnicodeDecodeError(*e.args[:4], msg)

    else:
        cipher = cipher_source

    if cipher == '':
        return ''

    # Get shuffled base-11 digits with key as seed
    base11_digits = get_base11_digits(key)

    # Get obstructor (cipher was XOR'd with obstructor in encryption)
    obstructor = abs(hash(key))

    # Convert base-94 cipher to base-10 integer using key, then un-obstruct
    base10_cipher_with_tag = baseN_to_base10(cipher, key) ^ obstructor

    # Convert base-10 cipher to base-11 cipher, i.e. tag and text cipher (also reverse XOR with obstructor)
    base11_cipher = base10_to_baseN(base10_cipher_with_tag, base11_digits)

    # Separate tag and base-10 cipher
    base11_cipher_split = base11_cipher.split()
    tag = base11_cipher_split[:-1]
    base10_cipher = int(base11_cipher_split[-1]) ^ obstructor  # un-obstruct again

    # Get text length and charset ords form tag
    length, *ords = [int(i) for i in tag]

    # Create charset from ords (which came from tag)
    charset = [chr(i) for i in ords]

    # Get text (base-N text) using charset which was derived earlier
    text = base10_to_baseN(base10_cipher, charset)

    # If text was comprised of 1 unique character, it would decrypt to a single character; correct this with length var
    if len(text) == 1:
        text *= length

    return text


# Shuffles base-11 digits with key as seed (0 or SPACE must be 0th digit as they can't be first char in base-11 cipher)
def get_base11_digits(key):
    key_error_check(key)

    # Get zero digit
    zeros = list(' 0')
    random.seed(key)
    z_index = random.randint(0, 1)
    zero = zeros[z_index]

    # Get list of non-zero digits
    non_zero = list('123456789' + zeros[1 - z_index])
    random.shuffle(non_zero, random.seed(key))

    return [zero] + non_zero


# Method documentation
generate_key.__doc__ = "Generates a string of length 94 with unique characters, using ASCII values 33-126"
encrypt.__doc__ = "Encrypts string with arbitrary character encoding into ASCII ciphertext"
decrypt.__doc__ = "Decrypts ASCII ciphertext into plaintext with arbitrary character encoding"
get_base11_digits.__doc__ = "Shuffles base-11 digits (0123456789 + SPACE) with key as seed"

