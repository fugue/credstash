from credsmash.util import padded_int


def test_zero():
    i = 0
    assert padded_int(i) == "0"*19


def test_ten():
    i = 10
    assert padded_int(i) == str(i).zfill(19)


def test_arbitrary_number():
    i = 98218329123
    assert padded_int(i) == str(i).zfill(19)


def test_huge_number():
    i = 12345678901234567890123
    assert padded_int(i) == str(i).zfill(19)
