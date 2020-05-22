# B94
<b>BASE-94 ENCRYPTION (B94): Private key text encryption algorithm</b>

Author: Samer N. Najjar<br>
Date launched: 18 October 2019<br>
Last updated: 21 May 2020

Keyspace size ~ 1.0873661567e+146

Supports arbitrary input character encoding (output ciphertext strictly ASCII)

---

File <code>B94.py</code> contains all cryptographic functionality; other files contain auxiliary tools or global constants.

See <code>key_fxns.py</code> for these tools:
* <code>is_key(key: str) -> bool:</code> checks if a string is a valid B94 key
* <code>approx_loc_in_keyspace(key: str) -> float:</code> returns a value between 0 and 1 (inclusive) indicating approximate location of key in keyspace, i.e. the integer distance from smallest base-94 key (not absolute location in keyspace)
* <code>get_keyspace() -> generator:</code> returns a Python generator for all possible keys as lists of characters instead of strings

See <code>radix.py</code> for these tools:
* <code>base10_to_base94(integer: int) -> str:</code> converts base-10 integer to base-94 string representation, using the first key in the keyspace as the preset numbering system (i.e. digits), which is equivalent to ASCII characters 33 to 126 (94 digits)
* <code>base94_to_base10(base94: str) -> int:</code> converts a base-94 string representation (using only ASCII characters 33-126) to base-10 integer
* <code>base10_to_baseN(integer: int, digits: iterable) -> str:</code> converts base-10 integer to arbitrary base-N string representation; 'digits' parameter must be populated with unique characters in an iterable (str, list, tuple, etc.) to act as a numbering system for the arbitrary base
* <code>baseN_to_base10(baseN: str, digits: iterable) -> str:</code> converts arbitrary base-N string representation to base-10 integer; again, 'digits' parameter must be populated with unique characters in an iterable (str, list, tuple, etc.) to act as a numbering system for the arbitrary base

See <code>global_constants.py</code> for foundational values:
* <code>KEY_CHARMAP =</code> first key in keyspace, i.e. smallest base-94 representation of length 94 with unique characters (equivalent to string of ASCII characters 33 to 126)
* <code>ASCII =</code> list of ASCII characters 33 to 126
* <code>KEY_LENGTH = 94</code> (length of any B94 key)
* <code>KEYSPACE_SIZE =</code> calculated number of possible keys, roughly equal to 1.0873661567×10<sup>146</sup>
* <code>KEYSPACE =</code> generator for all possible keys as lists of characters instead of strings; this variable is created upon importing the module, while <code>get_keyspace()</code> creates a new keyspace generator upon call

Finally, <code>misc.py</code> contains implicitly-used functions not relevant to the user, except for:
* <code>permute(n: int, r: int) -> int:</code> returns number of permutations of size <code>r</code> from population of size <code>n</code>; accurate for arbitrarily large integers, unlike the standard formula <code>n! / (n-r)!</code>

---
<small>© 2020 Najjar, Inc. All Rights Reserved.</small>