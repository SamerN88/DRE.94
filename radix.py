"""Functions for base conversion"""


from global_constants import KEY_CHARMAP


# Converts base-10 integer to base-94 representation with KEY_CHARMAP as fixed numbering system
def base10_to_base94(integer: int) -> str:
    digits = KEY_CHARMAP
    base = 94

    if integer < 0:
        msg = 'input for base-10 integer cannot be negative'
        raise ValueError(msg)
    elif integer == 0:
        return digits[0]

    bits = []
    while integer >= base:
        bit = digits[integer % base]
        bits.append(bit)
        integer //= base

    bits.append(digits[integer])
    return ''.join(reversed(bits))


# Converts base-94 representation to base-10 integer; only takes string whose characters exist in KEY_CHARMAP
def base94_to_base10(base94: str) -> int:
    result = 0
    length = len(base94)

    try:
        i = 0
        for digit in base94:
            pos = (length-1) - i
            denomination = KEY_CHARMAP.index(digit)
            result += denomination * (94 ** pos)
            i += 1

    # This is not checked before iteration to avoid having to iterate twice; just check during first iteration
    except ValueError:
        msg = "input for base-94 representation contains character(s) not included in preset digits " \
                "(ASCII codes 33 to 126)"
        raise ValueError(msg)

    return result


# Converts base-10 integer to base-N representation; supports arbitrary numbering system
def base10_to_baseN(integer, digits):
    digits = list(digits)
    base = len(digits)

    for ch in digits:
        if digits.count(ch) != 1:
            msg = 'all digits must be unique'
            raise ValueError(msg)

    if integer < 0:
        msg = 'input for base-10 integer cannot be negative'
        raise ValueError(msg)
    elif integer == 0:
        return digits[0]

    bits = []
    while integer >= base:
        bit = digits[integer % base]
        bits.append(bit)
        integer //= base

    bits.append(digits[integer])
    return ''.join(reversed(bits))


# Converts base-N representation to base-10 integer; supports arbitrary numbering system
def baseN_to_base10(baseN, digits):
    digits = list(digits)
    N = len(digits)  # N is old base

    for ch in digits:
        if digits.count(ch) != 1:
            msg = 'all digits must be unique'
            raise ValueError(msg)

    result = 0
    length = len(baseN)
    try:
        i = 0
        for digit in baseN:
            pos = (length-1) - i
            denomination = digits.index(digit)
            result += denomination * (N ** pos)
            i += 1

    # This is not checked before iteration to avoid having to iterate twice; just check during first iteration
    except ValueError:
        msg = f"input for base-{N} representation contains character(s) not included in given digits"
        raise ValueError(msg)

    return result
