import os
import tempfile
import shutil
import random
import threading
import array

from Crypto import Random
from nose.tools import assert_equal, assert_raises

from tahoefuse.blockcache import BitArray, BlockCachedFile
from tahoefuse.crypto import CryptFile


class TestBitArray(object):
    def test_basics(self):
        b = BitArray(0)
        assert_raises(IndexError, b.__getitem__, 0)

        b = BitArray(2)
        assert_equal(b[0], False)
        assert_equal(b[1], False)
        assert_raises(IndexError, b.__getitem__, 2)
        b[0] = 1
        assert_equal(b[0], True)
        assert_equal(b[1], False)
        b[1] = 1
        assert_equal(b[0], True)
        assert_equal(b[1], True)
        b[0] = 0
        assert_equal(b[0], False)
        assert_equal(b[1], True)

        b = BitArray(31)
        b[7] = 1
        assert_equal(repr(b), "<Bitarray '0000000100000000000000000000000'>")
        b[8] = 1
        assert_equal(repr(b), "<Bitarray '0000000110000000000000000000000'>")
        b[9] = 1
        assert_equal(repr(b), "<Bitarray '0000000111000000000000000000000'>")
        b[8] = 0
        assert_equal(repr(b), "<Bitarray '0000000101000000000000000000000'>")

    def test_serialize(self):
        random.seed(1234)
        b = BitArray(31)
        for j in range(31):
            b[j] = random.randint(0, 1)
        s = b.to_bytes()
        b2 = BitArray.from_bytes(s)
        assert_equal(repr(b), repr(b2))


class TestBlockCachedFile(object):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.file_name = os.path.join(self.tmpdir, 'test.dat')
        self.cache_data = Random.new().read(656)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _do_rw(self, blockfile, offset, length_or_data):
        if isinstance(length_or_data, bytes):
            write = True
            data = length_or_data
            length = len(data)
        else:
            write = False
            length = length_or_data

        x_offset = 0
        x_read_offset = x_offset
        x_data = []

        while True:
            if write:
                pos = blockfile.pre_write(offset, length)
            else:
                pos = blockfile.pre_read(offset, length)

            if pos is None:
                # cache ready
                if write:
                    return blockfile.write(offset, data)
                else:
                    return blockfile.read(offset, length)
            else:
                # cache not ready -- fill it in a purposefully dodgy way in small pieces
                c_offset, c_length = pos
                if c_offset > x_offset + 23 or c_offset < x_offset:
                    x_offset = (c_offset//13)*13
                    x_read_offset = x_offset
                    x_data = []
                x_data.append(self.cache_data[x_read_offset:x_read_offset+13])
                x_read_offset += 13
                x_offset, x_data = blockfile.receive_cached_data(x_offset, x_data)

    def _do_read(self, blockfile, offset, length):
        return self._do_rw(blockfile, offset, length)

    def _do_write(self, blockfile, offset, data):
        return self._do_rw(blockfile, offset, data)

    def test_basics(self):
        tmpf = tempfile.TemporaryFile()
        f = BlockCachedFile(tmpf, len(self.cache_data), block_size=7)
        data = self._do_read(f, 137, 91)
        assert_equal(data, self.cache_data[137:137+91])
        self._do_write(f, 131, "a"*31)
        data = self._do_read(f, 130, 91)
        assert_equal(data[0], self.cache_data[130])
        assert_equal(data[1:32], "a"*31)
        assert_equal(data[32:], self.cache_data[162:221])
        f.close()

    def _do_random_rw(self, f, sim_data, file_size, max_file_size, count):
        rnd = Random.new()

        for j in range(count):
            a = random.randint(0, max_file_size)
            b = random.randint(0, max_file_size)
            if a > b:
                a, b = b, a

            b = min(a + 39, b)

            if j % 2 == 0:
                # read op
                a = min(a, file_size-1)
                b = min(b, file_size)
                block = self._do_read(f, a, b - a)
                assert_equal(block, sim_data[a:b].tostring())
            else:
                # write op
                block = rnd.read(b-a)
                sim_data[a:b] = array.array('c', block)
                self._do_write(f, a, block)
                file_size = max(file_size, a + len(block))

        return file_size

    def test_random_rw(self):
        tmpf = tempfile.TemporaryFile()

        file_size = len(self.cache_data)
        max_file_size = 2*file_size

        random.seed(1234)

        for k in range(3):
            file_size = len(self.cache_data)
            sim_data = array.array('c', self.cache_data + "\x00"*(max_file_size-file_size))
            tmpf = tempfile.TemporaryFile()
            f = BlockCachedFile(tmpf, file_size, block_size=7)
            self._do_random_rw(f, sim_data, file_size, max_file_size, count=500)

        f.close()

    def test_write_past_end(self):
        # Check that write-past-end has POSIX semantics
        tmpf = tempfile.TemporaryFile()
        f = BlockCachedFile(tmpf, len(self.cache_data), block_size=7)

        self._do_write(f, len(self.cache_data) + 5, "a"*3)

        data = self._do_read(f, len(self.cache_data) - 1, 1+5+3)
        assert_equal(data, self.cache_data[-1] + "\x00"*5 + "a"*3)
        f.close()

    def test_truncate(self):
        # Check that truncate() works as expected
        tmpf = tempfile.TemporaryFile()
        f = BlockCachedFile(tmpf, len(self.cache_data), block_size=7)

        self._do_write(f, 0, b"b"*1237)
        assert_equal(self._do_read(f, 0, 15), b"b"*15)
        f.truncate(7)
        assert_equal(self._do_read(f, 0, 15), b"b"*7)
        f.truncate(0)
        assert_raises(EOFError, self._do_read, f, 0, 15)
        f.close()

    def test_on_top_cryptfile(self):
        tmpf = CryptFile(self.file_name, key=b"a"*32, mode='w+b')
        f = BlockCachedFile(tmpf, len(self.cache_data), block_size=37)

        self._do_write(f, 0, b"b"*1237)
        assert_equal(self._do_read(f, 0, 15), b"b"*15)
        f.truncate(7)
        assert_equal(self._do_read(f, 0, 15), b"b"*7)
        f.truncate(0)
        assert_raises(EOFError, self._do_read, f, 0, 15)
        f.close()

    def test_save_state(self):
        file_size = len(self.cache_data)
        max_file_size = 2*file_size
        sim_data = array.array('c', self.cache_data + "\x00"*(max_file_size-file_size))

        # Do random I/O on a file
        tmpf = CryptFile(self.file_name, key=b"a"*32, mode='w+b')
        f = BlockCachedFile(tmpf, file_size, block_size=7)
        file_size = self._do_random_rw(f, sim_data, file_size, max_file_size, count=17)

        # Save state
        state_file = CryptFile(self.file_name + '.state', key=b"b"*32, mode='w+b')
        f.save_state(state_file)
        state_file.close()
        f.close()

        # Restore state
        state_file = CryptFile(self.file_name + '.state', key=b"b"*32, mode='rb')
        tmpf = CryptFile(self.file_name, key=b"a"*32, mode='r+b')
        f = BlockCachedFile.restore_state(tmpf, state_file)
        state_file.close()

        # More random I/O
        for k in range(3):
            file_size = self._do_random_rw(f, sim_data, file_size, max_file_size, count=15)
        f.close()
