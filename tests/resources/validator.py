def succeed_validate(file_path, logger):
    # returning True is a must if using the validator, otherwise repex will throw an exception.  # NOQA
    return True


def fail_validate(file_path, logger):
    return False
