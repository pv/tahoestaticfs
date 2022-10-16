import pytest

def assert_equal(a, b, msg=""):
    assert a == b, msg

def assert_raises(exc, func, *a, **kw):
    with pytest.raises(exc):
        func(*a, **kw)
