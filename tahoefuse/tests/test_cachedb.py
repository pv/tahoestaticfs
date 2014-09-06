import os
import tempfile
import shutil
import random

from Crypto import Random
from nose.tools import assert_equal, assert_raises

from tahoefuse.cachedb import CryptFile


class TestCryptFile(object):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_create(self):
        # Test file creation in the different modes
        key = 'a'*32

        f = CryptFile(os.path.join(self.tmpdir, 'test.dat'), key=key, mode='w+b')
        f.write(b'foo')
        f.seek(0)
        assert_equal(f.read(), b'foo')
        f.close()

        f = CryptFile(os.path.join(self.tmpdir, 'test.dat'), key=key, mode='rb')
        assert_equal(f.read(), b'foo')
        assert_raises(IOError, f.write, b'bar')

        f = CryptFile(os.path.join(self.tmpdir, 'test.dat'), key=key, mode='r+b')
        assert_equal(f.read(), b'foo')
        f.write(b'bar')
        assert_equal(f.read(), b'')
        f.seek(0)
        assert_equal(f.read(), b'foobar')

        f = CryptFile(os.path.join(self.tmpdir, 'test.dat'), key=key, mode='w+b')
        f.seek(0)
        assert_equal(f.read(), b'')
        f.close()

    def test_random_rw(self):
        file_size = 1000000
        test_data = Random.new().read(file_size)
        key = "a"*32

        f = CryptFile(os.path.join(self.tmpdir, 'test.dat'), key=key, mode='w+b')
        f.write(test_data)
        f.close()

        f = CryptFile(os.path.join(self.tmpdir, 'test.dat'), key=key, mode='r+b')

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

    def test_truncate(self):
        key = "a"*32
        f = CryptFile(os.path.join(self.tmpdir, 'test.dat'), key=key, mode='w+b')
        f.write("b"*1237)
        f.truncate(15)
        f.seek(0)
        assert_equal(len(f.read()), 15)
        f.truncate(0)
        f.seek(0)
        assert_equal(len(f.read()), 0)
        f.close()
