import pandas as pd

from B94 import generate_key, encrypt, decrypt
from implicit import key_error_check, arg_check


# TODO: write decrypt_tabular_data

# Currently only supports CSV and Excel files
def encrypt_tabular_data(data_source, key, cols=(0, None), rows=(0, None), save_as=None, inplace=False):
    """Encrypts a tabular file using a B94 key, allowing user to specify which portion of the data to be encrypted.
    Allows user the option to save the encrypted data to a file. Currently only supports CSV and Excel files."""

    arg_check(inplace, 'inplace', bool)
    key_error_check(key)

    supported_types = ['CSV', 'Excel']

    # If data_source is a filename/path, read Dataframe from file
    if type(data_source) == str:
        file = data_source

        # Get file extension
        reverse = file[::-1]
        try:
            ext = reverse[:reverse.index('.')][::-1]
        except ValueError as e:
            msg = f"no file extension detected in given file path 'file': {file}"
            e.args = (msg,)
            raise

        # Select correct Pandas read method
        if ext == 'csv':
            read = pd.read_csv
        elif ext[:2] == 'xl':
            read = pd.read_excel
        else:
            msg = f'unrecognized file type (supported file types are {", ".join(supported_types)})'
            raise ValueError(msg)

        # Get Dataframe to be encrypted
        dataframe = read(file)

    # Else, expect data_source to be a Pandas Dataframe
    else:
        if inplace:
            dataframe = data_source
        else:
            dataframe = data_source.copy()

    # Due to how Pandas works, must include column names as data if they ever should be encrypted
    dataframe.loc[-1] = dataframe.columns  # add row for column names
    dataframe.index += 1  # shift index
    dataframe.sort_index(inplace=True)  # sort by index

    # Get bounds of specified portion of Dataframe to be encrypted
    x_start, x_end = cols
    y_start, y_end = rows

    # If default values used for ends, set to max indexes of Dataframe
    if x_end is None:
        x_end = len(dataframe.columns) - 1
    if y_end is None:
        y_end = len(dataframe.index) - 1

    # Iterate over specified ROW range of Dataframe (and encrypt)
    for y in range(y_start, y_end+1):
        row_slice = dataframe.iloc[y].copy()  # get row

        # Iterate over the entire row but...
        for i in range(len(row_slice)):
            # ...only encrypt the items within the specified COLUMN range
            if i in range(x_start, x_end+1):
                row_slice[i] = encrypt(str(row_slice[i]), key)  # encrypt the item

        # Set the value of that row in the Dataframe to the new encrypted row
        dataframe.iloc[y] = row_slice

    # After encryption, must reset column names to first row of data
    dataframe.columns = list(dataframe.iloc[0])
    dataframe.drop(0, inplace=True)
    dataframe.reset_index(drop=True, inplace=True)  # 0th index was dropped, so reset

    # If a save-as filename/path is given, save the encrypted Dataframe
    if save_as is not None:
        if type(save_as) != str:
            msg = f"keyword argument 'save_as' must be a path or filename with appropriate file extension"
            raise TypeError(msg)

        # Get 'save_as' file extension
        save_as_reverse = save_as[::-1]
        try:
            save_as_ext = save_as_reverse[:save_as_reverse.index('.')][::-1]
        except ValueError as e:
            msg = f"no file extension detected in 'save_as': {save_as}"
            e.args = (msg,)
            raise

        # Select save method based on 'save_as' file extension
        if save_as_ext == 'csv':
            dataframe.to_csv(save_as, index=False)  # exclude index
        elif save_as_ext[:2] == 'xl':
            dataframe.to_excel(save_as, index=False)  # exclude index
        else:
            msg = f'unrecognized \'save_as\' file type (supported file types are {", ".join(supported_types)})'
            raise ValueError(msg)

    return dataframe


# Currently only supports CSV and Excel files
def decrypt_tabular_data(data_source, key, cols=(0, None), rows=(0, None), save_as=None, inplace=False):
    """Decrypts a tabular file using a B94 key, allowing user to specify which portion of the data to be decrypted.
    Allows user the option to save the decrypted data to a file. Currently only supports CSV and Excel files."""

    arg_check(inplace, 'inplace', bool)
    key_error_check(key)

    supported_types = ['CSV', 'Excel']

    # If data_source is a filename/path, read Dataframe from file
    if type(data_source) == str:
        file = data_source

        # Get file extension
        reverse = file[::-1]
        try:
            ext = reverse[:reverse.index('.')][::-1]
        except ValueError as e:
            msg = f"no file extension detected in given file path 'file': {file}"
            e.args = (msg,)
            raise

        # Select correct Pandas read method
        if ext == 'csv':
            read = pd.read_csv
        elif ext[:2] == 'xl':
            read = pd.read_excel
        else:
            msg = f'unrecognized file type (supported file types are {", ".join(supported_types)})'
            raise ValueError(msg)

        # Get Dataframe to be decrypted
        dataframe = read(file)

    # Else, expect data_source to be a Pandas Dataframe
    else:
        if inplace:
            dataframe = data_source
        else:
            dataframe = data_source.copy()

    # Due to how Pandas works, must include column names as data in case they were encrypted
    dataframe.loc[-1] = dataframe.columns  # add row for column names
    dataframe.index += 1  # shift index
    dataframe.sort_index(inplace=True)  # sort by index

    # Get bounds of specified portion of Dataframe to be decrypted
    x_start, x_end = cols
    y_start, y_end = rows

    # If default values used for ends, set to max indexes of Dataframe
    if x_end is None:
        x_end = len(dataframe.columns) - 1
    if y_end is None:
        y_end = len(dataframe.index) - 1

    # Iterate over specified ROW range of Dataframe (and decrypt)
    for y in range(y_start, y_end+1):
        row_slice = dataframe.iloc[y].copy()  # get row

        # Iterate over the entire row but...
        for i in range(len(row_slice)):
            # ...only decrypt the items within the specified COLUMN range
            if i in range(x_start, x_end+1):
                row_slice[i] = decrypt(str(row_slice[i]), key)  # decrypt the item

        # Set the value of that row in the Dataframe to the new decrypted row
        dataframe.iloc[y] = row_slice

    # After decryption, must reset column names to first row of data
    dataframe.columns = list(dataframe.iloc[0])
    dataframe.drop(0, inplace=True)
    dataframe.reset_index(drop=True, inplace=True)  # 0th index was dropped, so reset

    # If a save-as filename/path is given, save the decrypted Dataframe
    if save_as is not None:
        if type(save_as) != str:
            msg = f"keyword argument 'save_as' must be a path or filename with appropriate file extension"
            raise TypeError(msg)

        # Get 'save_as' file extension
        save_as_reverse = save_as[::-1]
        try:
            save_as_ext = save_as_reverse[:save_as_reverse.index('.')][::-1]
        except ValueError as e:
            msg = f"no file extension detected in 'save_as': {save_as}"
            e.args = (msg,)
            raise

        # Select save method based on 'save_as' file extension
        if save_as_ext == 'csv':
            dataframe.to_csv(save_as, index=False)  # exclude index
        elif save_as_ext[:2] == 'xl':
            dataframe.to_excel(save_as, index=False)  # exclude index
        else:
            msg = f'unrecognized \'save_as\' file type (supported file types are {", ".join(supported_types)})'
            raise ValueError(msg)

    return dataframe
