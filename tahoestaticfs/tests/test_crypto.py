import os
import tempfile
import shutil
import random
import threading

from nose.tools import assert_equal, assert_raises

from tahoestaticfs.crypto import CryptFile


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
