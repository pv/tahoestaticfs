import numpy as np
import struct


BLOCK_SIZE = 131072

class BlockCachedFile(object):
    """
    I am temporary file, caching data for a remote file. I support
    overwriting data. I cache remote data on a per-block basis and
    keep track of which blocks need still to be retrieved. Before each
    read/write operation, my pre_read or pre_write method needs to be
    called --- these give the ranges of data that need to be retrieved
    from the remote file and fed to me (via receive_cached_data)
    before the read/write operation can succeed. I am fully
    synchronous.
    """

    def __init__(self, f, initial_cache_size, block_size=None):
        if block_size is None:
            block_size = BLOCK_SIZE

        self.f = f
        self.actual_size = 0
        self.block_size = block_size

        self.cache_size = initial_cache_size
        num_blocks, remainder = divmod(self.cache_size, self.block_size)
        if remainder != 0:
            num_blocks += 1
        self.cache_map = BitArray(num_blocks)
        self.first_uncached_block = 0

    def save_state(self, f):
        f.truncate(0)
        f.seek(0)
        f.write(struct.pack('<QQQQ', self.actual_size, self.block_size, self.cache_size, self.first_uncached_block))
        f.write(self.cache_map.to_bytes())

    @classmethod
    def restore_state(cls, f, state_file):
        s = state_file.read(4*8)
        actual_size, block_size, cache_size, first_uncached_block = \
            struct.unpack('<QQQQ', s)
        cache_map = BitArray.from_bytes(state_file.read())

        self = cls.__new__(cls)
        self.f = f
        self.actual_size = actual_size
        self.block_size = block_size
        self.cache_size = cache_size
        self.first_uncached_block = first_uncached_block
        self.cache_map = cache_map
        return self

    def _get_block_range(self, offset, length, inner=False):
        """
        For inner=False: compute block range fully containing [offset, offset+length)
        For inner=True: compute block range fully contained in [offset, offset+length)
        """
        if offset >= self.cache_size:
            length = 0
        else:
            length = min(length, self.cache_size - offset)

        if length == 0:
            return 0, 0, 0, 0

        start_block, start_skip = divmod(offset, self.block_size)
        end_block, end_skip = divmod(offset + length, self.block_size)

        if inner:
            if start_skip > 0:
                start_block += 1
                start_skip = self.block_size - start_skip

            if offset + length == self.cache_size and end_skip > 0:
                # the last block can be partial
                end_skip = 0
                end_block += 1
        else:
            if end_skip > 0:
                end_block += 1
                if offset + length == self.cache_size:
                    # last block can be partial
                    end_skip = 0
                else:
                    end_skip = self.block_size - end_skip

        return start_block, end_block, start_skip, end_skip

    def _pad_file(self, new_size):
        """
        Append zero bytes to self.f so that its size grows to new_size
        """
        if new_size <= self.actual_size:
            return

        self.f.seek(0, 2)

        nblocks, remainder = divmod(new_size - self.actual_size, self.block_size)
        if nblocks > 0:
            blk = "\x00" * self.block_size
            for j in range(nblocks):
                self.f.write(blk)
        if remainder > 0:
            self.f.write("\x00" * remainder)

        self.actual_size = new_size

    def receive_cached_data(self, offset, data_list):
        """
        Write full data blocks to file, unless they were not written
        yet. Returns (new_offset, new_data_list) containing unused,
        possibly reuseable data. data_list is a list of strings.
        """
        data_size = sum(len(data) for data in data_list)

        start_block, end_block, start_skip, end_skip = self._get_block_range(
            offset, data_size, inner=True)

        if start_block == end_block:
            # not enough data
            return offset, data_list

        data = "".join(data_list)[start_skip:]

        if start_block < self.first_uncached_block:
            i = self.first_uncached_block - start_block
            start_block = self.first_uncached_block
        else:
            i = 0

        for j in xrange(start_block, end_block):
            if not self.cache_map[j]:
                pos = j * self.block_size
                block = data[i*self.block_size:(i+1)*self.block_size]
                block = block[:(self.cache_size - pos)]
                self._pad_file(pos)
                self.f.seek(pos)
                self.f.write(block)

                self.actual_size = max(self.actual_size, pos + len(block))
                self.cache_map[j] = True
            i += 1

        if start_block <= self.first_uncached_block:
            self.first_uncached_block = max(self.first_uncached_block, end_block)

        # Return trailing data for possible future use
        if end_skip > 0:
            data_list = [data[-end_skip:]]
            offset += data_size - len(data_list[0])
        else:
            data_list = []
            offset += data_size
        return (offset, data_list)

    def get_size(self):
        return max(self.actual_size, self.cache_size)

    def get_file(self):
        # Pad file to full size before returning file handle
        self._pad_file(self.get_size())
        return self.f

    def close(self):
        self.f.close()
        self.cache_map = BitArray(0)

    def truncate(self, size):
        if size < self.actual_size:
            self.f.truncate(size)
            self.actual_size = size
        elif size > self.actual_size:
            self._pad_file(size)

        self.cache_size = min(size, self.cache_size)

    def write(self, offset, data):
        if offset > self.actual_size:
            # Explicit POSIX behavior for write-past-end
            self._pad_file(offset)

        if len(data) == 0:
            # noop
            return

        # Sanity check cache status
        if self.pre_write(offset, len(data)) is not None:
            raise RuntimeError("attempt to write before caching")

        # Perform write
        self.f.seek(offset)
        self.f.write(data)
        self.actual_size = max(self.actual_size, offset + len(data))

        # Update cache status for completely overwritten blocks
        start_block, end_block, _, _ = self._get_block_range(offset, len(data), inner=True)
        for j in xrange(max(start_block, self.first_uncached_block), end_block):
            self.cache_map[j] = True
        if start_block <= self.first_uncached_block:
            self.first_uncached_block = max(self.first_uncached_block, end_block)

    def read(self, offset, length):
        if offset >= self.actual_size and offset >= self.cache_size:
            raise EOFError("read past end of file")

        # Sanity check cache status
        if self.pre_read(offset, length) is not None:
            raise RuntimeError("attempt to read before caching")

        # Perform read
        self.f.seek(offset)
        return self.f.read(length)

    def pre_read(self, offset, length):
        """
        Return (offset, length) of the first cache fetch that need to be
        performed and the results fed into `receive_cached_data` before a read
        operation can be performed. There may be more than one fetch
        necessary. Return None if no fetch is necessary.
        """
        start_block, end_block, _, _ = self._get_block_range(offset, length)

        # Combine consequent blocks into a single read
        j = start_block
        while j < end_block and self.cache_map[j]:
            j += 1
        if j >= end_block:
            return None

        for k in xrange(j+1, end_block):
            if self.cache_map[k]:
                end = k
                break
        else:
            end = end_block

        start_pos = j * self.block_size
        end_pos = end * self.block_size
        if start_pos < self.cache_size:
            return (start_pos, max(self.cache_size, end_pos) - start_pos)

        return None

    def pre_write(self, offset, length):
        """
        Similarly to pre_read, but for write operations.
        """
        start_block, end_block, start_skip, end_skip = self._get_block_range(offset, length)

        if start_block < end_block:
            if (offset % self.block_size) != 0 and not self.cache_map[start_block]:
                start_pos = start_block * self.block_size
                end_pos = (start_block + 1) * self.block_size
                if start_pos < self.cache_size:
                    return (start_pos, max(self.cache_size, end_pos) - start_pos)

            if ((offset + length) % self.block_size) != 0 and not self.cache_map[end_block - 1]:
                start_pos = (end_block - 1) * self.block_size
                end_pos = end_block * self.block_size
                if start_pos < self.cache_size:
                    return (start_pos, max(self.cache_size, end_pos) - start_pos)

        # No reads required
        return None


class BitArray(object):
    """
    Mutable array of n bits
    """
    def __init__(self, n):
        if n < 0:
            raise ValueError("must have n >= 0")
        self.n = n
        nbytes, off = divmod(n, 8)
        if off != 0:
            nbytes += 1
        self.value = np.zeros([nbytes], np.uint8)

    def to_bytes(self):
        s = struct.pack('<Q', self.n)
        s += self.value.tostring()
        return s

    @classmethod
    def from_bytes(cls, s):
        n = struct.unpack('<Q', s[:8])[0]
        self = cls.__new__(cls)
        self.n = n
        self.value = np.fromstring(s[8:], dtype=np.uint8)
        return self

    def __getitem__(self, i):
        if i < 0 or i >= self.n:
            raise IndexError("out of bounds get")
        n, j = divmod(i, 8)
        return bool((self.value[n] >> j) & 0x1)

    def __setitem__(self, i, value):
        if i < 0 or i >= self.n:
            raise IndexError("out of bounds set")
        n, j = divmod(i, 8)
        r = (0x1 << j)
        if value:
            self.value[n] |= r
        else:
            r ^= 0xff
            self.value[n] &= r

    def __repr__(self):
        r = "".join('1' if self[i] else '0' for i in range(self.n))
        return "<Bitarray %r>" % (r,)
