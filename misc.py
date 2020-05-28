"""Miscellaneous functions, including method to save ciphers, keys, or any text to a text file."""


# Ciphers/keys/text can be saved manually in any text format, but this method expedites the saving process
def save(string, file):
    """Saves ciphers or keys or any text to the given file path; more efficient than manual saving."""

    save_file = open(file, 'w')
    save_file.write(string)
    save_file.close()


# Returns number of permutations of size r from population n; accurate for very large integers, unlike n! / (n-r)!
def permute(n, r):
    """Returns number of permutations of size r from population of size n;
    accurate for arbitrarily large integers, unlike standard formula n! / (n-r)!"""

    product = 1
    for i in range(n - r + 1, n + 1):
        product *= i
    return product
