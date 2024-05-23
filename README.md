# DRE.94
#### **Dynamic Radix Encryption with base-94 cipher: private key text encryption cryptosystem**

<u>Author:</u> Samer N. Najjar (<a href="https://snajjar.me" target="_blank">About me</a>)<br>
<u>Date launched:</u> 18 October 2019<br>
<u>Last updated:</u> 28 December 2020

Keyspace size: 94! (~ 1.0873661567×10<sup>146</sup>)

Supports arbitrary plaintext character encoding (ciphertext strictly ASCII).

---
File `DRE_94.py` contains main cryptographic functionality; other files contain necessary supplemental code or extra tools.

**Main file**

`DRE_94.py` has the following cryptographic functionality:
* `generate_key(seed=None) -> str` generates a DRE.94 key, which is a string of length 94, all distinct characters, shuffled from the list of ASCII characters 33 to 126 (inclusive). The user can pass a seed to this function that will always generate the same key. The `seed` parameter defaults to `None` (NOTE: seedless key-generation is more secure against attacks, but for the purposes of this algorithm, in many cases using a seed is just practical).
* `encrypt(text_source: str, key: str, fromfile: bool=False):` encrypts a string with arbitrary character encoding into ASCII ciphertext. The `text_source` parameter can be the literal text intended for encryption, or the path of a text file which contains the text intended for encryption; if a path/filename is passed, then the `fromfile` parameter must be set to `True` otherwise the path/filename will be treated as literal text.
* `decrypt(cipher_source: str, key: str, fromfile: bool=False):` decrypts DRE.94 ASCII ciphertext into plaintext with arbitrary character encoding. Like the `encrypt` function, the `cipher_source` parameter can be the literal ciphertext intended for decryption, or the path of a text file which contains the ciphertext intended for decryption; if a path/filename is passed, then the `fromfile` parameter must be set to `True` otherwise the path/filename will be treated as literal ciphertext.

**Ancillary files**

See `key_ops.py` for functions that operate on a key or relate to keyspace:
* `is_key(key: str) -> bool:` checks if a string is a valid DRE.94 key; returns `True` or `False`.
* `approx_loc_in_keyspace(key: str) -> float:` returns a value between 0 and 1 (inclusive) indicating approximate location of key in keyspace, i.e. the integer distance from the smallest base-94 key (not absolute location in keyspace).
* `get_keyspace() -> generator:` returns a Python generator for all possible DRE.94 keys as lists of characters instead of strings.

See `radix.py` for functions that convert between bases:
* `base10_to_base94(integer: int) -> str:` converts base-10 integer to base-94 string representation, using the first key in the keyspace as the preset numbering system (i.e. the symbol set), which is equivalent to ASCII characters 33 to 126 (94 symbols).
* `base94_to_base10(base94: str) -> int:` converts a base-94 string representation (using only ASCII characters 33-126) to base-10 integer.
* `base10_to_baseN(integer: int, symbol_set: iterable) -> str:` converts base-10 integer to arbitrary base-N string representation; `symbol_set` parameter must be populated with distinct characters in an iterable (str, list, tuple, etc.) to act as a numbering system for the arbitrary base.
* `baseN_to_base10(baseN: str, symbol_set: iterable) -> str:` converts arbitrary base-N string representation to base-10 integer; again, `symbol_set` parameter must be populated with distinct characters in an iterable (str, list, tuple, etc.) to act as a numbering system for the arbitrary base.

See `global_constants.py` for fundamental values:
* `KEY_CHARMAP =` first key in keyspace, i.e. smallest base-94 representation (string) of length 94 with distinct characters (equivalent to string of ASCII characters 33 to 126).
* `ASCII =` list of ASCII characters 33 to 126
* `KEY_LENGTH = 94` (length of any DRE.94 key)
* `KEYSPACE_SIZE =` calculated number of possible keys, equal to 94! (roughly equal to 1.0873661567×10<sup>146</sup>).
* `KEYSPACE =` generator for all possible keys as lists of characters instead of strings; this variable is created upon importing the module, while `get_keyspace()` creates a new keyspace generator upon call.

See `misc.py` for these miscellaneous functions:
* `save(string: str, file: str) -> None:` an easy-to-use method for saving ciphers, keys, or any text to a text file. The user specifies the path/filename to which the given string will be saved as text (file could be pre-existing or new). Simply more efficient than manually saving text into a text file.
* `permute(n: int, r: int) -> int:` returns number of permutations of size `r` from population of size `n`; accurate for arbitrarily large integers, unlike the standard formula `n! / (n-r)!`.

Finally, `implicit.py` contains functionality that is used implicitly throughout the library; this is not intended for direct use by users. See function definitions inside the file for documentation.

**Useful tools**

See `experimental.py` for functions that test DRE.94's algorithm:
* `reliance_test(trials: int, verbose: bool=True): -> bool` tests reliability of DRE.94's algorithm by checking if decrypted values match original values using random keys, for any number of trials. Verbose mode prints the key, original text, and ciphertext for every trial, then prints 'PASS' or 'FAIL' upon completion. Verbose is `True` by default. The function returns `True` or `False` (pass or fail, respectively).
* `brute_force(key=None, time_limit=None, verbose: bool=True) -> bool:` brute-forces DRE.94's algorithm by successively iterating over the keyspace until a predetermined fixed key is reached. User can specify the fixed key with the `key` parameter, otherwise it is randomly generated upon call. User can specify a `time_limit` value in seconds, which will terminate the run if the time limit is reached before brute forcing completes. Verbose mode prints preliminary information about the fixed key and start time, then prints a report upon successful brute forcing, which contains information about the amount of keyspace iterated over and the time elapsed. Verbose is `True` by default. The function returns `True` or `False` (brute forcing will only fail if a time limit is set). (NOTE: on standard computers, a successful brute forcing will likely take a tremendous amount of time.)
* `collision_test(key=None, time_limit=None, verbose: bool=True) -> bool:` attempts to produce a collision by randomly generating keys until one equals a predetermined fixed key. User can specify the fixed key with the `key` parameter, otherwise it is randomly generated upon call, although this likely has no effect on the results as the generated keys are random. User can specify a `time_limit` value in seconds, which will terminate the run if the time limit is reached before a collision is encountered. Verbose mode prints the fixed key and the start time, then prints a report upon encountering a collision, which contains the number of keys tried and the time elapsed. Verbose is `True` by default. The function returns `True` or `False` (collision test will only fail if a time limit is set). (NOTE: since keys are randomly generated in a collision test, the test could theoretically run for infinite time; in this way, the collision test is a very rough measure of the vastness of the keyspace; if the keyspace were small enough, the test could end quite quickly. However, also note that this is **not a very good test**; it is essentially a [Bogosort](https://en.wikipedia.org/wiki/Bogosort) algorithm, where the key characters are shuffled randomly until they happen to be in the same order as the fixed key.)

See `tabular.py` for tabular cryptography:
* `encrypt_tabular_data(data_source, key: str, cols: tuple=(0, None), rows: tuple=(0, None), save_as=None, inplace: bool=False):` encrypts tabular data (such as a CSV or Excel file) using a DRE.94 key. For the first argument `data_source`, the user can pass a path/filename as a string and that file will be automatically loaded as a Pandas DataFrame and encrypted (currently, only CSV and Excel file types are supported). Alternatively, the user can directly pass a Pandas DataFrame; the function can tell the difference. The user can specify the portion of the data to encrypt using the keyword arguments `cols` and `rows`, which take a tuple (or list) with 2 integers, which are the start and end indexes of the tabular portion. For example, `cols=(1,3)` and `rows=(0,5)` will encrypt only the cells within columns 1 to 3 and rows 0 to 5, inclusive. If these bounds are not specified, the entire table is encrypted by default. The optional `save_as` argument takes a path/filename as a string, and the encrypted tabular data will be saved to that file (again, only CSV and Excel file types are supported). The optional `inplace` argument is used when passing a Pandas DataFrame; if set to `True`, the encrypted DataFrame will overwrite the original DataFrame. The default value is `False`. The function always returns the encrypted DataFrame.
* `decrypt_tabular_data(data_source, key: str, cols: tuple=(0, None), rows: tuple=(0, None), save_as=None, inplace: bool=False):` decrypts tabular data (such as a CSV or Excel file) using a DRE.94 key. Takes the same parameters as `encrypt_tabular_data` (see documentation for `encrypt_tabular_data`); while `encrypt_tabular_data` loads original data and saves/returns encrypted data, `decrypt_tabular_data` loads encrypted data and saves/returns decrypted data. The function always returns the decrypted DataFrame.

**Limitations**

DRE.94's algorithm is good for encrypting modestly sized strings and text files, roughly under ten thousand characters long. But for text of higher-order size, such as a string of length 50,000 or a 30 KB text file, the algorithm becomes inefficient and encryption is time-consuming (you can still encrypt such large text without errors, it would just take time). Moreover, the efficiency of the algorithm varies inversely with the diversity of the characters being encrypted; a 5000-character string containing only ASCII characters encrypts much faster than a 5000-character string containing 5000 distinct characters. These are general limitations to keep in mind when encrypting arbitrarily large text.


**Author's note**

The security of DRE.94 has not been extensively tested—you are welcome to challenge my algorithm! If you break the algorithm or find any bugs, please let me know by opening an issue on Github or emailing me at [s.najjar612@gmail.com]().

---
<small>© 2020 Najjar, Inc. All Rights Reserved.</small>
