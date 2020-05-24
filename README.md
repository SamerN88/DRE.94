# B94
#### **BASE-94 ENCRYPTION (B94): Private key text encryption algorithm**

<u>Author:</u> Samer N. Najjar ([About me](https://najjarcv.imfast.io/))<br>
<u>Date launched:</u> 18 October 2019<br>
<u>Last updated:</u> 23 May 2020

Keyspace size: 94! (~ 1.0873661567e+146)

Supports arbitrary input character encoding (output ciphertext strictly ASCII)

---
File `B94.py` contains main cryptographic functionality; other files contain auxiliary tools or global constants.

**Main file**

`B94.py` has the following cryptographic functionality:
* `generate_key(seed=None) -> str` generates a B94 key, which is a string of length 94, all distinct characters, shuffled from the list of ASCII characters 33 to 126 (inclusive). The user can pass a seed to this function that will always generate the same key. The `seed` parameter defaults to `None` (NOTE: seedless key-generation is more secure against attacks, but for the purposes of this algorithm, in many cases using a seed is just practical).
* `encrypt(text_source: str, key: str, fromfile: bool=False):` encrypts a string with arbitrary character encoding into ASCII ciphertext. The `text_source` parameter can be the literal text intended for encryption, or the path of a text file which contains the text intended for encryption; if a path/filename is passed, then the `fromfile` parameter must be set to `True` otherwise the path/filename will be treated as literal text.
* `decrypt(cipher_source: str, key: str, fromfile: bool=False):` decrypts B94 ASCII ciphertext into plaintext with arbitrary character encoding. Like the `encrypt` function, the `cipher_source` parameter can be the literal ciphertext intended for decryption, or the path of a text file which contains the ciphertext intended for decryption; if a path/filename is passed, then the `fromfile` parameter must be set to `True` otherwise the path/filename will be treated as literal ciphertext.

**Ancillary files**

See `key_fxns.py` for functions that operate on a key or relate to keyspace:
* `is_key(key: str) -> bool:` checks if a string is a valid B94 key; returns `True` or `False`
* `approx_loc_in_keyspace(key: str) -> float:` returns a value between 0 and 1 (inclusive) indicating approximate location of key in keyspace, i.e. the integer distance from the smallest base-94 key (not absolute location in keyspace)
* `get_keyspace() -> generator:` returns a Python generator for all possible B94 keys as lists of characters instead of strings

See `radix.py` for functions that convert between bases:
* `base10_to_base94(integer: int) -> str:` converts base-10 integer to base-94 string representation, using the first key in the keyspace as the preset numbering system (i.e. the symbol set), which is equivalent to ASCII characters 33 to 126 (94 symbols)
* `base94_to_base10(base94: str) -> int:` converts a base-94 string representation (using only ASCII characters 33-126) to base-10 integer
* `base10_to_baseN(integer: int, symbol_set: iterable) -> str:` converts base-10 integer to arbitrary base-N string representation; `symbol_set` parameter must be populated with distinct characters in an iterable (str, list, tuple, etc.) to act as a numbering system for the arbitrary base
* `baseN_to_base10(baseN: str, symbol_set: iterable) -> str:` converts arbitrary base-N string representation to base-10 integer; again, `symbol_set` parameter must be populated with distinct characters in an iterable (str, list, tuple, etc.) to act as a numbering system for the arbitrary base

See `global_constants.py` for fundamental values:
* `KEY_CHARMAP =` first key in keyspace, i.e. smallest base-94 representation (string) of length 94 with distinct characters (equivalent to string of ASCII characters 33 to 126)
* `ASCII =` list of ASCII characters 33 to 126
* `KEY_LENGTH = 94` (length of any B94 key)
* `KEYSPACE_SIZE =` calculated number of possible keys, equal to 94! (roughly equal to 1.0873661567×10<sup>146</sup>)
* `KEYSPACE =` generator for all possible keys as lists of characters instead of strings; this variable is created upon importing the module, while `get_keyspace()` creates a new keyspace generator upon call

See `experimental.py` for functions that test B94's algorithm:
* `reliance_test(trials: int, verbose: bool=True, super_verbose: bool=False): -> bool` tests reliability of algorithm by checking if decrypted values match original values using random keys, for any number of trials. Verbose mode prints PASS or FAIL, super-verbose mode prints the key, original text, and ciphertext for every trial. Returns `True` or `False`
* `brute_force(key=None) -> None:` brute-forces B94. User has the option to specify a key to be used in brute-forcing; `key` parameter defaults to `None` (in which case a random key is generated upon call). This function is strictly verbose and prints a report upon successful brute-forcing (NOTE: on normal computers, this will likely take forever).

Finally, `misc.py` contains implicitly-used functions not relevant to the user, except for:
* `permute(n: int, r: int) -> int:` returns number of permutations of size `r` from population of size `n`; accurate for arbitrarily large integers, unlike the standard formula `n! / (n-r)!`

**Limitations**

B94's algorithm is good for encrypting modestly sized strings and text files, roughly under ten thousand characters long. But for text of higher-order size, such as a string of length 50,000 or a 30 KB text file, the algorithm becomes inefficient and encryption is very time-consuming (you can still encrypt such large text without errors, it would just take time). Moreover, the efficiency of the algorithm varies inversely with the diversity of the characters being encrypted; a 5000-character string using only ASCII characters encrypts much faster than a 5000-character string that uses 5000 distinct characters. These are general limitations to keep in mind when encrypting arbitrarily large text.

---
<small>© 2020 Najjar, Inc. All Rights Reserved.</small>