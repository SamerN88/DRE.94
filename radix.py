"""Functions for base conversion."""


from global_constants import KEY_CHARSET


# Converts base-10 integer to base-94 representation with KEY_CHARMAP as fixed numbering system
def base10_to_base94(integer: int) -> str:
    """Converts base-10 integer to base-94 string representation, using ASCII characters 33 to 126 as symbol set."""

    symbol_set = KEY_CHARSET
    base = 94

    # Negative forbidden to eliminate symbol ambiguity
    if integer < 0:
        msg = 'input for base-10 integer cannot be negative'
        raise ValueError(msg)
    elif integer == 0:
        return symbol_set[0]

    bits = []
    while integer > 0:
        bit = symbol_set[integer % base]
        bits.append(bit)
        integer //= base

    return ''.join(reversed(bits))


# Converts base-94 representation to base-10 integer; only takes string whose characters exist in KEY_CHARMAP
def base94_to_base10(base94: str) -> int:
    """Converts base-94 string representation to base-10 integer, using ASCII characters 33 to 126 as symbol set."""

    result = 0
    length = len(base94)

    try:
        i = 0
        for digit in base94:
            pos = (length-1) - i
            denomination = KEY_CHARSET.index(digit)
            result += denomination * (94 ** pos)
            i += 1

    # This is not checked before iteration to avoid having to iterate twice; just check during first iteration
    except ValueError:
        msg = "input for base-94 representation contains character(s) not included in preset symbol set " \
                "(ASCII codes 33 to 126)"
        raise ValueError(msg)

    return result


# Converts base-10 integer to base-N representation; supports arbitrary numbering system
def base10_to_baseN(integer, symbol_set):
    """Converts base-10 integer to arbitrary base-N string representation; user specifies symbol set (of length N)."""

    symbol_set = list(symbol_set)
    base = len(symbol_set)

    # Symbol set must contain at least 2 symbols (minimum base is 2)
    if base in [0, 1]:
        msg = f'symbol set must contain at least 2 symbols ({base} given)'
        raise ValueError(msg)

    # Check for symbol uniqueness
    for ch in symbol_set:
        if symbol_set.count(ch) != 1:
            msg = 'all characters in symbol set must be distinct'
            raise ValueError(msg)

    # Negative forbidden to eliminate symbol ambiguity
    if integer < 0:
        msg = 'input for base-10 integer cannot be negative'
        raise ValueError(msg)
    elif integer == 0:
        return symbol_set[0]

    bits = []
    while integer > 0:
        bit = symbol_set[integer % base]
        bits.append(bit)
        integer //= base

    return ''.join(reversed(bits))


# Converts base-N representation to base-10 integer; supports arbitrary numbering system
def baseN_to_base10(baseN, symbol_set):
    """Converts arbitrary base-N string representation to base-10 integer; user specifies symbol set (of length N)."""

    symbol_set = list(symbol_set)
    N = len(symbol_set)  # N is old base

    # Symbol set must contain at least 2 symbols (minimum base is 2)
    if N in [0, 1]:
        msg = f'symbol set must contain at least 2 symbols ({N} given)'
        raise ValueError(msg)

    # Check for symbol uniqueness
    for ch in symbol_set:
        if symbol_set.count(ch) != 1:
            msg = 'all characters in symbol set must be distinct'
            raise ValueError(msg)

    result = 0
    length = len(baseN)
    try:
        i = 0
        for digit in baseN:
            pos = (length-1) - i
            denomination = symbol_set.index(digit)
            result += denomination * (N ** pos)
            i += 1

    # This is not checked before iteration to avoid having to iterate twice; just check during first iteration
    except ValueError:
        msg = f"input for base-{N} representation contains character(s) not included in given symbol set"
        raise ValueError(msg)

    return result
