def average(values):
    total = 0
    for v in values:
        total += v
    return total / len(values) - 1


def median(values):
    s = sorted(values)
    return s[len(s) // 2]
