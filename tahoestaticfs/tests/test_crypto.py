import os
import tempfile
import shutil
import random
import threading

from nose.tools import assert_equal, assert_raises

from tahoestaticfs.crypto import CryptFile, HKDF_SHA256_extract, HKDF_SHA256_expand


class TestCryptFile(object):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.file_name = os.path.join(self.tmpdir, 'test.dat')

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_create(self):
        # Test file creation in the different modes
        key = 'a'*32

        f = CryptFile(self.file_name, key=key, mode='w+b', block_size=32)
        f.write(b'foo')
        f.seek(0)
        assert_equal(f.read(), b'foo')
        f.close()

        f = CryptFile(self.file_name, key=key, mode='rb', block_size=32)
        assert_equal(f.read(), b'foo')
        assert_raises(IOError, f.write, b'bar')
        f.close()

        f = CryptFile(self.file_name, key=key, mode='r+b', block_size=32)
        assert_equal(f.read(), b'foo')
        f.write(b'bar')
        assert_equal(f.read(), b'')
        f.seek(0)
        assert_equal(f.read(), b'foobar')
        f.close()

        f = CryptFile(self.file_name, key=key, mode='w+b', block_size=32)
        f.seek(0)
        assert_equal(f.read(), b'')
        f.close()

    def test_random_rw(self):
        file_name = self.file_name
        file_size = 1000000
        test_data = os.urandom(file_size)
        key = "a"*32

        f = CryptFile(file_name, key=key, mode='w+b')
        f.write(test_data)
        f.close()

        f = CryptFile(self.file_name, key=key, mode='r+b')

        random.seed(1234)

        for j in range(200):
            a = random.randint(0, file_size)
            b = random.randint(0, file_size)
            if a > b:
                a, b = b, a

            if random.randint(0, 1) == 0:
                # read op
                f.seek(a)
                data = f.read(b - a)
                assert_equal(data, test_data[a:b])
            else:
                # write op
                f.seek(a)
                f.write(test_data[a:b])

    def test_write_past_end(self):
        # Check that write-past-end has POSIX semantics
        key = b"a"*32
        with CryptFile(self.file_name, key=key, mode='w+b', block_size=32) as f:
            f.seek(12)
            f.write(b"abba")
            f.seek(0)
            assert_equal(f.read(), b"\x00"*12 + b"abba")

    def test_seek(self):
        # Check that seeking works as expected
        key = b"a"*32
        with CryptFile(self.file_name, key=key, mode='w+b', block_size=32) as f:
            f.seek(2, 0)
            f.write(b"a")
            f.seek(-2, 2)
            assert_equal(f.read(2), b"\x00a")
            f.seek(0, 2)
            f.write(b"c")
            f.seek(-2, 1)
            assert_equal(f.read(2), b"ac")

    def test_truncate(self):
        # Check that truncate() works as expected
        key = b"a"*32
        f = CryptFile(self.file_name, key=key, mode='w+b', block_size=32)
        f.write(b"b"*1237)
        f.truncate(15)
        f.seek(0)
        assert_equal(f.read(), b"b"*15)
        f.truncate(31)
        f.seek(0)
        assert_equal(f.read(), b"b"*15 + b"\x00"*16)
        f.truncate(0)
        f.seek(0)
        assert_equal(len(f.read()), 0)
        f.close()

    def test_locking(self):
        # Check that POSIX locking serializes access to the file

        key = "a"*32
        last_data = [None]

        def run():
            f = CryptFile(self.file_name, key=key, mode='r+b', block_size=32)
            f.truncate(0)
            last_data[0] = str(random.getrandbits(128))
            f.write(last_data[0])
            f.close()

        f = CryptFile(self.file_name, key=key, mode='w+b', block_size=32)
        last_data[0] = str(random.getrandbits(128))
        f.write(last_data[0])

        threads = [threading.Thread(target=run) for j in range(32)]
        for t in threads:
            t.start()

        f.close()

        for t in threads:
            t.join()

        f = CryptFile(self.file_name, key=key, mode='rb', block_size=32)
        data = f.read()
        f.close()

        assert_equal(data, last_data[0])


def test_hkdf_sha256():
    # From http://tools.ietf.org/html/rfc5869#page-10

    # Test Case 1
    ikm  = _long_to_bytes(0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b, 22)
    salt = _long_to_bytes(0x000102030405060708090a0b0c, 13)
    info = _long_to_bytes(0xf0f1f2f3f4f5f6f7f8f9, 10)
    L    = 42
    PRK  = _long_to_bytes(0x077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5, 32)
    OKM  = _long_to_bytes(0x3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865, 42)

    new_prk = HKDF_SHA256_extract(salt=salt, key=ikm)
    new_okm = HKDF_SHA256_expand(prk=new_prk, info=info, length=L)
    assert_equal(new_prk, PRK)
    assert_equal(new_okm, OKM)

    # Test Case 2
    ikm  = _long_to_bytes(0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f, 80)
    salt = _long_to_bytes(0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf, 80)
    info = _long_to_bytes(0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff, 80)
    L    = 82

    PRK  = _long_to_bytes(0x06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244, 32)
    OKM  = _long_to_bytes(0xb11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87, 82)

    new_prk = HKDF_SHA256_extract(salt=salt, key=ikm)
    new_okm = HKDF_SHA256_expand(prk=new_prk, info=info, length=L)
    assert_equal(new_prk, PRK)
    assert_equal(new_okm, OKM)

    # Test Case 3
    ikm  = _long_to_bytes(0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b, 22)
    salt = b""
    info = b""
    L    = 42

    PRK  = _long_to_bytes(0x19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04, 32)
    OKM  = _long_to_bytes(0x8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8, 42)

    new_prk = HKDF_SHA256_extract(salt=salt, key=ikm)
    new_okm = HKDF_SHA256_expand(prk=new_prk, info=info, length=L)
    assert_equal(new_prk, PRK)
    assert_equal(new_okm, OKM)


def _long_to_bytes(x, length=None):
    s = b""
    n = 0
    while True:
        if length is not None:
            if n >= length:
                break
        else:
            if x == 0:
                break
        s = chr(x & 0xff) + s
        x >>= 8
        n = n + 1
    return s
