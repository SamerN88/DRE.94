from global_constants import *
from key_ops import approx_loc_in_keyspace
import time
from datetime import datetime
from radix import baseN_to_base10, base10_to_baseN


def is_prime(n):
    # Note: not prime = composite

    # Check for integer
    if type(n) != int:
        if type(n) == float and int(n) == n:
            pass
        else:
            raise TypeError('input must be integer')

    # Negative numbers, 0, and 1 are not prime
    if n < 2:
        return False

    # Even numbers except 2 are not prime
    if 0 == n % 2 and n > 2:
        return False

    # By Theorem, if n is composite, it has a prime divisor that doesn't exceed sqrt(n); don't check further
    for i in range(3, int(n ** 0.5)+1, 2):
        if 0 == n % i:
            return False

    # If all tests of compositeness fail, the number is prime
    return True


def nth_prime(n):
    if n < 1:
        raise ValueError('input must be >= 1')

    if n == 1:
        return 2

    integer = 3
    primes = 2
    while primes < n:
        integer += 2
        if is_prime(integer):
            primes += 1

    return integer


########################################################################################################################
########################################################################################################################
########################################################################################################################
# FIRST HASH FUNCTION ——————————————————————————————————————————————————————————————————————————————————————————————————


# # Size of hash table is the smallest prime greater than key length
# # PRIME_SIZE = KEY_LENGTH * 2
# # while not is_prime(PRIME_SIZE):
# #     PRIME_SIZE += 1
# # PRIME_SIZE = nth_prime(88888)
# PRIME_SIZE = nth_prime(888)
#
# # The prime used for double hashing is the largest prime smaller than key length
# # CONST_PRIME = KEY_LENGTH
# # while not is_prime(CONST_PRIME):
# #     CONST_PRIME -= 1
# # CONST_PRIME = nth_prime(888)
# CONST_PRIME = nth_prime(100)
#
#
# def step_size(seed, const=CONST_PRIME):
#     key = 0
#     for i in range(len(seed) - 1, -1, -1):
#         num = ord(seed[i])
#         key += num * (KEY_LENGTH ** i)
#     return const - (key % const)
#
#
# def hash_seed(seed, size=PRIME_SIZE):
#     hash_idx = 0
#
#     for i in range(len(seed)):
#         num = ord(seed[i])
#         hash_idx = (hash_idx * KEY_LENGTH + num) % size
#
#     return hash_idx
#
#
# def insert_char(hash_table, char, idx, step, size):
#     while hash_table[idx] != '':
#         idx = (idx + step) % size
#
#     hash_table[idx] = char
#
#
# # average runtime: 9.10262632369995e-05 s
# def gen_key(seed=None):
#     if seed is None:
#         seed = str(time.time())
#
#     key_hash_table = [''] * PRIME_SIZE
#
#     idx = hash_seed(seed, len(key_hash_table))
#     step = step_size(seed)
#     size = len(key_hash_table)
#
#     for i in range(len(KEY_CHARMAP)):
#         idx = (idx * (i + 1)) % PRIME_SIZE
#
#         insert_char(key_hash_table, KEY_CHARMAP[i], idx, step, size)
#
#     return ''.join(key_hash_table)


########################################################################################################################
########################################################################################################################
########################################################################################################################
# SECOND HASH FUNCTION —————————————————————————————————————————————————————————————————————————————————————————————————

# The issue with the first hash function was that it only had access to a small finite
# portion of the keyspace (when we say 'access' we refer to the set of all unique keys
# that the function is able to generate; if the function cannot generate all theoretically
# possible keys, then it does not have access to the full keyspace and thus is sub-optimal).
# Since we want a key-generating function to have access to the full keyspace, we desire
# u = k
# where u is the number of unique keys a function can generate and k is the size of the
# keyspace.
# We define the set U as the set of all unique keys a function can generate.
# The first hash function used two prime numbers p and q to generate a key from a seed. The
# larger p and q are, the larger U is. The problem was that this relationship was not very
# steep, meaning that p and q would have to be astronomically large in order for U to equal
# the keyspace, which would make the function impractically slow, i.e. it would take years to
# generate a single key. For all practical values of p and q, we always had u < k.
# The second hash function resolved this issue by eliminating the use of p and q and instead
# using a base b which can be any integer. A similar relationship held where the larger b is,
# the larger U is. However, the relationship in this case is slightly different; previously,
# p and q determined a strict maximum u, whereas b determines the frequency of collisions in
# a given set of keys; for example, given b = 1 and a set of 1,000,000 keys, the number of unique
# keys in that set is about 217 (i.e. u = 217). In a set of 3,000,000 keys, u = 319. So for the
# second hash function, when we discuss the relationship between b and u, we use the frequency
# of duplicates in a finite set of keys to approximate the 'access' that the function has to
# the keyspace. To quantify this access, we choose a large enough set of random keys of size s so
# that we can approximate this set to the keyspace, so s ~ k (the actual keyspace has size 94!).
# The frequency of duplicates in that set is approximately representative of the frequency of
# duplicates in a set of k keys; then, the number of unique keys in that large set is considered
# u, the 'access' of the function to the keyspace.
# Given this approximate definition of u, the relationship between b and u was much better than
# the relationship achieved in the first hash function with p and q. Even with a very small
# value of b, such as b = 10, and a set of 1,000,000 randomly generated keys, there were zero
# duplicates, i.e. u = 1,000,000 = k (here, the set of 1,000,000 keys is meant to approximate
# the keyspace, so we assume k = 1,000,000). With b = 5 and a set of k = 3,000,000 randomly
# generated keys, we had u = 2,557,116, which is close to k. These are very small values of b,
# so we can achieve incredibly better access with the second hash function over the first.
# At this point, with k = 94! as the size of the actual keyspace, the goal is to be able to
# generate a set of k keys with zero collisions, or very close. But it is not computationally
# viable to create such a set, so we extrapolate from smaller sets to attempt to create a formula
# that approximates the relationship between b and u. Once this formula is found, we can find a
# value of b for which u(b) equals k, the size of the keyspace. To create such a formula, we
# generate a set of 3,000,000 keys using bases 3, 4, and 5 and plot u vs. b to find a relation
# between u and b. So, we plot the points (3, u(3)), (4, u(4)), and (3, u(5)) where u(b) is the
# number of unique keys in a set of 3,000,000 keys when generated with base b. Upon plotting
# these points, the relation appears linear, with the formula
# u(b) = 928327b - 2089997
# This linear model is then used to approximate how large b has to be so that u(b) = 94!, or in
# other words, how large b has to be so that we can generate every possible theoretical key
# before generating collisions:
# 94! = 928327b - 2089997
# b = (94! + 2089997) / 928327
# But since b must be an integer, and the value above is not, we use the ceiling of this value:
# b = ceiling((94! + 2089997) / 928327)
# b = 11713180341159344501168799922525855760328720761130816221815952184310614672353376302771448
#     (continued) 9845262946632556055841532547626569827226828477465379
# Note that this value for minimum required base is only approximate, since it was found by
# approximating the keyspace to 3,000,000 for computational practicality. It may be possible to
# find the true minimum required base using pure math, but this approach has not been tried yet.


# Based on the rough linear model
# u(b) = 928327b - 2089997
# where u(b) is the number of unique keys that the key generation algorithm has access to,
# and b is the base used in the seed hashing algorithm, the minimum base required to have
# access to all theoretically possible keys is
# 11713180341159344501168799922525855760328720761130816221815952184310614672353376302771448
# (continued) 9845262946632556055841532547626569827226828477465379
# or roughly 1.171 * 10^140. The number 2 * 10^140 was chosen for simplicity's sake.
# Note that the current model for u(b) is not exact, and thus the minimum required base to
# access the full keyspace might be much smaller than the currently decided value, assigned
# to the variable `MIN_BASE` below.
# EDIT: min base should be a large prime to avoid hash collisions
# Explanation of how large primes are collision-resistant:
#   The keyspace has size H=94!. Consider an integer seed n.
#   Suppose the base b is the number 94!, so b=H. Then
#       (1)    key(n) = key(n+b) = key(n+2b) = ... = key(n+xb)
#   because b contains all factors 1-94, which are the moduli used when constructing the key.
#   On the other hand, if the base is a large prime p, i.e. it shares no factors with H, (and
#   it itself is not a factor of H) then
#       (2)    key(n) != key(n+p) != key(n+2p) != ... != key(n+xp)
#   The more factors the base shares with H, the stronger the key generation algorithm
#   exhibits the property (1). Therefore, a large prime is farthest from this unwanted
#   property, so using a large prime as a base is collision resistant.
#   Note that no matter what the base, collisions happen at intervals of H integers.
# old value: MIN_BASE = 2 * 10**140
M512 = 2 ** 512 - 1  # large Mersenne prime


# This hash function is least significant bit first (LSB-first) so that keys generated randomly
# within close proximity in time are far apart due to the rightmost digits (which are treated
# as the most significant bits) being different, while the leftmost digits are the same.
# Example:
# Since the key generation function uses the quantity `seconds since Epoch` as a default seed
# if no seed is passed, two keys randomly generated immediately after one another take the
# following seeds:
# seed1 = 1607892643.2334201
# seed2 = 1607892643.2368448
# The time difference between generating the two keys is about 0.0034248 seconds.
# Since only the few rightmost digits are different, we want those to have a large influence
# on the generated key. Hence, the hash function is LSB-first.
# We use Horner's method to allow very large seeds without much computational overhead.
def hash_seed2(seed, size, base=M512):
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


# Some notes:
#   - for integer seeds, collisions happen at intervals of 94! (size of the keyspace)
#   - for str seeds of 1 character which has a small ord() value (roughly less than 80)
#     OR small int seeds (roughly less than 80), close seeds produce close keys; for
#     just slightly longer strings (or single-character strings with higher ord() value)
#     OR slightly larger ints, this issue is eliminated easily
#   - collisions between an int seed and a str seed can systematically be found if you
#     start with the str and compute the int as follows:
#         Formula:
#           int_seed = sum(ord(ch)*(M512**i) for i, ch in enumerate(str_seed))
#         Example:
#           str_seed = 'str'
#           int_seed = ord('s') + ord('t')*(M512**1) + ord('r')*(M512**2)
#           key(str_seed) == key(int_seed)
#     where M512 is the Mersenne prime 2**512 - 1. Hence, the algorithm makes no
#     fundamental distinction between strings and integers.
#   - int seeds run faster than str seeds; int seeds generate keys in constant time
#     O(1) whereas str seeds generate keys in linear time O(N) where N=len(seed)
def gen_key2(seed=None, base=M512):
    # Default seed is microseconds since epoch
    if seed is None:
        seed = time.time_ns() // 1000

    charset = list(KEY_CHARMAP)

    # First pass generates intermediate key
    intermediate = []
    for size in range(KEY_LENGTH, 0, -1):
        # Hash the seed to get index in charset
        idx = hash_seed2(seed, size, base)
        ch = charset[idx]

        # Add char to intermediate key, and remove it from charset
        intermediate.append(ch)
        charset.remove(ch)

    # Second pass generates final key, using intermediate key as charset
    # (purpose of 2nd pass is to ensure close seeds do not produce close keys)
    key = []
    for size in range(KEY_LENGTH, 0, -1):
        # Hash the seed to get index in intermediate key
        idx = hash_seed2(seed, size, base)
        ch = intermediate[idx]

        # Add char to final key, and remove it from intermediate key
        key.append(ch)
        intermediate.remove(ch)

    return ''.join(key)


def avg_runtime(fxn, trials=1000, args=None, kwargs=None, verbose=False):
    if args is None:
        args = []
    if kwargs is None:
        kwargs = {}

    start = time.time()

    for _ in range(trials):
        fxn(*args, **kwargs)

    total_time = time.time() - start
    avg_time = total_time / trials

    if verbose:
        print(f'Average runtime of {trials} trials for function \'{fxn.__name__}\': {avg_time} s')

    return avg_time


# Generator of all possible printable ASCII strings up to a given length
# (in this case, printable ASCII excludes all whitespace characters except SPACE)
# A custom charset can be passed as well in place of the ASCII default
def string_space(start_len=1, end_len=95, charset=None):
    # Printable ASCII sorted by standard lexicon (letters, digits, then symbols)
    ASCII_BY_LEX = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ '

    if charset is None:
        charset = ASCII_BY_LEX
    else:
        # Keep 1 copy of each character, but preserve order
        temp_list = list(charset)
        charset = []
        for ch in temp_list:
            if ch not in charset:
                charset.append(ch)

        charset = ''.join(charset)

    start_str = charset[0] * start_len  # default is 'a'
    end_str = charset[-1] * end_len  # default is ' '*95

    symbol_set = '\0' + charset

    start_int = baseN_to_base10(start_str, symbol_set)
    end_int = baseN_to_base10(end_str, symbol_set)

    for i in range(start_int, end_int + 1):
        string = base10_to_baseN(i, symbol_set)
        if '\0' in string:
            continue
        else:
            yield string


# Since Python lists can have a maximum length of 536870912 (on 32-bit systems), a specialized
# function is needed to generate 1 billion keys and check for uniqueness; this is done with 2
# passes, where each pass generates a list of 500 million keys. The lists are converted to sets
# to remove duplicates, then the intersection between the two sets is examined to further rule
# out duplicates.
# WARNING: many gigabytes of memory are needed to generate lists of keys this large (roughly
# 75 GB per list or set; given 2 lists and 2 sets, roughly 300 GB are needed). Note that the
# program may encounter a MemoryError for which there is appropriate handling.
# This function performs two passes as described above, with a parameter for total number of
# keys to be generated.
def two_passes(num_keys, default=True):
    # GET AVERAGE RUNTIME

    # Add avg time of appending keys to list
    avg_time = avg_runtime([].append, args=[KEY_CHARMAP])
    if default:
        # Add avg time of generating keys with default int seeds
        avg_time += avg_runtime(gen_key2)
    else:
        # Add avg time of generating keys with str seeds
        avg_time += avg_runtime(gen_key2, args=['abc'])

        # Add avg time of iterating over string space
        str_space = string_space()
        avg_time += avg_runtime(lambda: next(str_space))

    # START TEST

    # Since two passes of equal size are used, num_keys is ensured to be an even number
    num_keys += 0 if num_keys % 2 == 0 else 1
    max_list_len = num_keys // 2

    # NOTE: this does not account for the time it takes to convert the large lists to sets, so the
    # real time may be significantly larger than the estimated time
    estimated_time = num_keys * avg_time

    print(f'Generating {num_keys} keys (with {"default integer" if default else "custom string"} seeds)')
    print('Estimated time:', estimated_time, 's', f'({estimated_time / 3600} hr)')
    print()

    print('Start time:', datetime.now())

    if not default:
        start_seed = next(string_space())
        str_space = string_space()

    key_sets = {0: set(), 1: set()}

    start = time.time()
    for i in range(2):
        print(f'Pass {i + 1} of {2}')
        keys = []

        try:
            if default:
                # default seeds
                for j in range(max_list_len):
                    keys.append(gen_key2())
            else:
                # string space seeds
                for j in range(max_list_len):
                    s = next(str_space)
                    keys.append(gen_key2(s))

        except KeyboardInterrupt:
            print(f'*** INTERRUPTED AT {j + (i * max_list_len)} KEYS ***')
            break
        except MemoryError:
            print(f'*** MEMORY ERROR AT {j + (i * max_list_len)} KEYS ***')
            break
        finally:
            key_sets[i] = set(keys)

    end = time.time()

    print('End time:', datetime.now())
    print()

    print('Time elapsed:', end - start, 's')
    print()

    set1 = key_sets[0]
    set2 = key_sets[1]
    unique_keys = len(set1) + len(set2) - len(set1.intersection(set2))

    print('# unique keys:', unique_keys)
    if not default:
        print('First seed:', start_seed)
        print('Last seed:', s)


# Finding probability of collision given a set of n keys:
# https://www.ilikebigbits.com/2018_10_20_estimating_hash_collisions.html
def main():
    default = False  # True: default seeds, False: string space seeds
    num_keys = 300000

    # Uncomment the following lines of code to test more than 536870912 keys
    # (max size of a Python list on a 32-bit system)
    # two_passes(num_keys, default=default)
    # return

    # GET AVERAGE RUNTIME ==============================================================================================

    # Add avg time of appending keys to list
    avg_time = avg_runtime([].append, args=[KEY_CHARMAP])
    if default:
        # Add avg time of generating keys with default int seeds
        avg_time += avg_runtime(gen_key2)
    else:
        # Add avg time of generating keys with str seeds
        avg_time += avg_runtime(gen_key2, args=['abc'])

        # Add avg time of iterating over string space
        str_space = string_space()
        avg_time += avg_runtime(lambda: next(str_space))

    estimated_time = num_keys * avg_time

    # START TEST =======================================================================================================

    print(f'Generating {num_keys} keys (with {"default integer" if default else "custom string"} seeds)')
    print('Estimated time:', estimated_time, 's', f'({estimated_time / 3600} hr)')
    print()

    print('Start time:', datetime.now())

    if not default:
        start_seed = next(string_space())
        str_space = string_space()

    # Use a list then convert to set because lists are faster to append to, and
    # this allows us to interrupt the program and still get useful info mid-run
    keys = []
    start = time.time()
    try:
        if default:
            # default seeds
            for i in range(num_keys):
                keys.append(gen_key2())
        else:
            # string space seeds
            for i in range(num_keys):
                s = next(str_space)
                keys.append(gen_key2(s))
    except KeyboardInterrupt:
        print(f'*** INTERRUPTED AT {i} KEYS ***')

    end = time.time()

    print('End time:', datetime.now())
    print()

    print('Time elapsed:', end - start, 's')
    print()

    print('# unique keys:', len(set(keys)))
    if not default:
        print('First seed:', start_seed)
        print('Last seed:', s)


if __name__ == '__main__':
    main()


# Output when testing unique keys of 1 million keys with bases 1-20:

# # keys: 1000000
#
# Base 1:
#   time = 68.79036331176758
#   # unique keys = 279
#
# Base 2:
#   time = 68.73583483695984
#   # unique keys = 15444
#
# Base 3:
#   time = 73.54919505119324
#   # unique keys = 279888
#
# Base 4:
#   time = 72.97248888015747
#   # unique keys = 735111
#
# Base 5:
#   time = 74.30896520614624
#   # unique keys = 864892
#
# Base 6:
#   time = 74.27898120880127
#   # unique keys = 925936
#
# Base 7:
#   time = 73.33787178993225
#   # unique keys = 956369
#
# Base 8:
#   time = 73.31199789047241
#   # unique keys = 986217
#
# Base 9:
#   time = 137.5749387741089  <-- This is a fluke; should be around 75 sec
#   # unique keys = 995612
#
# Base 10:
#   time = 82.56889295578003
#   # unique keys = 1000000
#
# Base 11:
#   time = 80.54210782051086
#   # unique keys = 1000000
#
# Base 12:
#   time = 80.73391604423523
#   # unique keys = 1000000
#
# Base 13:
#   time = 80.89487504959106
#   # unique keys = 1000000
#
# Base 14:
#   time = 80.75563073158264
#   # unique keys = 1000000
#
# Base 15:
#   time = 80.3513810634613
#   # unique keys = 1000000
#
# Base 16:
#   time = 80.31370806694031
#   # unique keys = 1000000
#
# Base 17:
#   time = 81.88031601905823
#   # unique keys = 1000000
#
# Base 18:
#   time = 80.91395092010498
#   # unique keys = 1000000
#
# Base 19:
#   time = 80.88909196853638
#   # unique keys = 1000000
#
# Base 20:
#   time = 80.7712631225586
#   # unique keys = 1000000
#
# 1
# 2  **
# 3  ****************************
# 4  **************************************************************************
# 5  **************************************************************************************
# 6  *********************************************************************************************
# 7  ************************************************************************************************
# 8  ***************************************************************************************************
# 9  ****************************************************************************************************
# 10 ****************************************************************************************************
# 11 ****************************************************************************************************
# 12 ****************************************************************************************************
# 13 ****************************************************************************************************
# 14 ****************************************************************************************************
# 15 ****************************************************************************************************
# 16 ****************************************************************************************************
# 17 ****************************************************************************************************
# 18 ****************************************************************************************************
# 19 ****************************************************************************************************
# 20 ****************************************************************************************************


# WITH STRING DEFAULT SEED
# Finding u when k = 25,000,000; results: u = k (success)

# Total number of keys being generated: 25000000
# Estimated time it will take: 18260.38360595703 s (5.0723287794325085 hr)
#
# Start time: 2020-12-13 22:28:13.624108
# End time: 2020-12-14 03:43:14.681580
#
# Time elapsed: 18901.057397842407 s
#
# # unique keys: 25000000


# WITH INTEGER DEFAULT SEED
# Finding u when k = 80,000,000; results: u = k (success)

# Total number of keys being generated: 80000000
# Estimated time: 6956.35986328125 s (1.9323221842447917 hr)
#
# Start time: 2020-12-16 14:02:56.094058
# End time: 2020-12-16 15:56:25.024287
#
# Time elapsed: 6808.9275159835815 s
#
# # unique keys: 80000000


# WITH STRING SPACE SEEDS (note inefficient testing algorithm; fixed)

# Total number of keys being generated: 20000000
# Estimated time: 3947.268009185791 s (1.096463335884942 hr)
#
# Start time: 2020-12-16 21:10:01.483017
# End time: 2020-12-16 23:20:56.474768
#
# Time elapsed: 7854.990701913834 s
#
# # unique keys: 20000000
