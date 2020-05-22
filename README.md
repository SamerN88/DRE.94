# B94
#### <b>BASE-94 ENCRYPTION (B94): Private key text encryption algorithm</b>

Author: Samer N. Najjar<br>
Date launched: 18 October 2019<br>
Last updated: 21 May 2020

Keyspace size ~ 1.0873661567e+146

Supports arbitrary input character encoding (output ciphertext strictly ASCII)

---
File <code>B94.py</code> contains all cryptographic functionality; other files contain auxiliary tools or global constants.

<b>Main file</b>

<code>B94.py</code> has the following functionality:
* <code>generate_key(seed=None) -> str</code> generates a B94 key, which is a string of length 94, all unique characters, shuffled from the list of ASCII characters 33 to 126 (inclusive). The user can pass a seed to this function that will always generate the same key. The <code>seed</code> parameter defaults to <code>None</code> (NOTE: seedless key-generation is more secure against attacks, but for the purposes of this algorithm, in most cases this is not a real danger and using a seed as a 'passcode' is practical).
* <code>encrypt(text_source: str, key: str, fromfile: bool=False):</code> encrypts a string with arbitrary character encoding into ASCII ciphertext. The <code>text_source</code> parameter can be the literal text intended for encryption, or the path of a text file which contains the text intended for encryption; if a path/filename is passed, then the <code>fromfile</code> parameter must be set to <code>True</code> otherwise the path/filename will be treated as literal text.
* <code>decrypt(cipher_source: str, key: str, fromfile: bool=False):</code> decrypts B94 ASCII ciphertext into plaintext with arbitrary character encoding. Like the <code>encrypt</code> function, the <code>cipher_source</code> parameter can be the literal ciphertext intended for decryption, or the path of a text file which contains the ciphertext intended for decryption; if a path/filename is passed, then the <code>fromfile</code> parameter must be set to <code>True</code> otherwise the path/filename will be treated as literal ciphertext.
* <code>get_base11_digits(key: str) -> list:</code> shuffles the 11 characters <code>0123456789</code> and <code>SPACE</code> using a B94 key as a seed for the shuffle, to create a base-11 numbering system consistent with the key; this is instrumental to B94 encryption. Returns the 11 digits in a list

<b>Ancillary files</b>

See <code>key_fxns.py</code> for functions that operate on a key or relate to keyspace:
* <code>is_key(key: str) -> bool:</code> checks if a string is a valid B94 key; returns <code>True</code> or <code>False</code>
* <code>approx_loc_in_keyspace(key: str) -> float:</code> returns a value between 0 and 1 (inclusive) indicating approximate location of key in keyspace, i.e. the integer distance from the smallest base-94 key (not absolute location in keyspace)
* <code>get_keyspace() -> generator:</code> returns a Python generator for all possible keys as lists of characters instead of strings

See <code>radix.py</code> for functions that convert between bases:
* <code>base10_to_base94(integer: int) -> str:</code> converts base-10 integer to base-94 string representation, using the first key in the keyspace as the preset numbering system (i.e. digits), which is equivalent to ASCII characters 33 to 126 (94 digits)
* <code>base94_to_base10(base94: str) -> int:</code> converts a base-94 string representation (using only ASCII characters 33-126) to base-10 integer
* <code>base10_to_baseN(integer: int, digits: iterable) -> str:</code> converts base-10 integer to arbitrary base-N string representation; <code>digits</code> parameter must be populated with unique characters in an iterable (str, list, tuple, etc.) to act as a numbering system for the arbitrary base
* <code>baseN_to_base10(baseN: str, digits: iterable) -> str:</code> converts arbitrary base-N string representation to base-10 integer; again, <code>digits</code> parameter must be populated with unique characters in an iterable (str, list, tuple, etc.) to act as a numbering system for the arbitrary base

See <code>global_constants.py</code> for fundamental values:
* <code>KEY_CHARMAP =</code> first key in keyspace, i.e. smallest base-94 representation of length 94 with unique characters (equivalent to string of ASCII characters 33 to 126)
* <code>ASCII =</code> list of ASCII characters 33 to 126
* <code>KEY_LENGTH = 94</code> (length of any B94 key)
* <code>KEYSPACE_SIZE =</code> calculated number of possible keys, roughly equal to 1.0873661567×10<sup>146</sup>
* <code>KEYSPACE =</code> generator for all possible keys as lists of characters instead of strings; this variable is created upon importing the module, while <code>get_keyspace()</code> creates a new keyspace generator upon call

See <code>experimental.py</code> for functions that test B94's algorithm:
* <code>reliance_test(trials: int, verbose: bool=True, super_verbose: bool=False): -> bool</code> tests reliability of algorithm by checking if decrypted values match original values using random keys, for any number of trials. Verbose mode prints PASS or FAIL, super-verbose mode prints the key, original text, and ciphertext for every trial. Returns <code>True</code> or <code>False</code>
* <code>brute_force(key=None) -> None:</code> brute-forces B94. User has the option to specify a key to be used in brute-forcing; <code>key</code> parameter defaults to <code>None</code> (in which case a random key is generated upon call). This function is strictly verbose and prints a report upon successful brute-forcing (NOTE: computationally taxing).

Finally, <code>misc.py</code> contains implicitly-used functions not relevant to the user, except for:
* <code>permute(n: int, r: int) -> int:</code> returns number of permutations of size <code>r</code> from population of size <code>n</code>; accurate for arbitrarily large integers, unlike the standard formula <code>n! / (n-r)!</code>

---
<small>© 2020 Najjar, Inc. All Rights Reserved.</small>