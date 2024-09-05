from math import ceil, sqrt
import string
import random


def random_string_alphadigit(count):
    """
    return random string that contains digits and lowercase chars
    """
    # using random.choices()
    # generating random strings
    return ''.join(random.choices(
        string.ascii_lowercase + string.digits, k=count))


def mean_value(data):
    """ average value of list """
    cnt = len(data)
    if not cnt:
        return None

    return sum(data) / cnt


def rms(data):
    """
    root mean square
    """
    cnt = len(data)
    mean = mean_value(data)
    if mean is None:
        return None
    diff_summ = sum([(x - mean) ** 2 for x in data])

    return sqrt(diff_summ / cnt)

