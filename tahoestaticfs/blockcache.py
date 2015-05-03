import os
import struct
import errno


BLOCK_SIZE = 131072
BLOCK_UNALLOCATED = -1
BLOCK_ZERO = -2


def _ceildiv(a, b):
    """Compute ceil(a/b)"""
    n, remainder = divmod(a, b)
    if remainder > 0:
        n += 1
    return n


class BlockStorage(object):
    """
    File storing fixed-size blocks of data.
    """

    def __init__(self, f, block_size):
        self.f = f
        self.block_size = block_size
        self.block_map = []
        self.free_block_idx = 0
        self.zero_block = b"\x00"*self.block_size

    def save_state(self, f):
        f.truncate(0)
        f.seek(0)
        f.write(b"BLK2")
        f.write(struct.pack('<Qq', self.block_size, len(self.block_map)))
        f.write(struct.pack('<%dq' % (len(self.block_map),), *self.block_map))

    @classmethod
    def restore_state(cls, f, state_file):
        hdr = state_file.read(4)
        if hdr != b"BLK2":
            raise ValueError("invalid block storage state file")
        s = state_file.read(2 * 8)
        block_size, num_blocks = struct.unpack('<Qq', s)

        s = state_file.read(num_blocks * 8)
        block_map = list(struct.unpack('<%dq' % (num_blocks,), s))

        self = cls.__new__(cls)
        self.f = f
        self.block_size = block_size
        self.block_map = block_map
        self.free_block_idx = 0
        self.zero_block = b"\x00"*self.block_size
        return self

    def _get_free_block_idx(self):
        while self.free_block_idx in self.block_map:
            self.free_block_idx += 1
        return self.free_block_idx

    def __contains__(self, idx):
        if not idx >= 0:
            raise ValueError("Invalid block index")
        if idx >= len(self.block_map):
            return False
        return self.block_map[idx] != BLOCK_UNALLOCATED

    def __getitem__(self, idx):
        if idx not in self:
            raise KeyError("Block not allocated")

        block_idx = self.block_map[idx]
        if block_idx >= 0:
            self.f.seek(self.block_size * block_idx)
            block = self.f.read(self.block_size)
            if len(block) < self.block_size:
                # Partial block (end-of-file): consider zero-padded
                block += b"\x00"*(self.block_size - len(block))
            return block
        elif block_idx == BLOCK_ZERO:
            return self.zero_block
        else:
            raise IOError(errno.EIO, "Corrupted block map data")

    def __setitem__(self, idx, data):
        if not idx >= 0:
            raise ValueError("Invalid block index")
        if idx >= len(self.block_map):
            self.block_map.extend([BLOCK_UNALLOCATED]*(idx+1 - len(self.block_map)))

        if data is None or data == self.zero_block:
            block_idx = self.block_map[idx]
            if block_idx >= 0 and block_idx < self.free_block_idx:
                self.free_block_idx = block_idx
            self.block_map[idx] = BLOCK_ZERO
        else:
            if len(data) > self.block_size:
                raise ValueError("Too large data block")

            block_idx = self.block_map[idx]
            if not block_idx >= 0:
                block_idx = self._get_free_block_idx()

            self.block_map[idx] = block_idx

            if len(data) < self.block_size:
                # Partial blocks are OK at the end of the file
                # only. Such blocks will be automatically zero-padded
                # by POSIX if writes are done to subsequent blocks.
                # Other blocks need explicit padding.
                self.f.seek(0, 2)
                pos = self.f.tell()
                if pos > self.block_size * block_idx + len(data):
                    data += b"\x00" * (self.block_size - len(data))

            self.f.seek(self.block_size * block_idx)
            self.f.write(data)

    def truncate(self, num_blocks):
        self.block_map = self.block_map[:num_blocks]
        self.free_block_idx = min(self.free_block_idx, num_blocks)
        num_blocks = 0
        if self.block_map:
            num_blocks = max(0, max(self.block_map) + 1)
        self.f.truncate(self.block_size * num_blocks)


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
        self.size = initial_cache_size
        self.storage = BlockStorage(f, block_size)
        self.block_size = self.storage.block_size
        self.first_uncached_block = 0
        self.cache_size = initial_cache_size

    def save_state(self, f):
        self.storage.save_state(f)
        f.write(struct.pack('<QQQ', self.size, self.cache_size, self.first_uncached_block))

    @classmethod
    def restore_state(cls, f, state_file):
        storage = BlockStorage.restore_state(f, state_file)
        s = state_file.read(3 * 8)
        size, cache_size, first_uncached_block = struct.unpack('<QQQ', s)

        self = cls.__new__(cls)
        self.storage = storage
        self.size = size
        self.cache_size = cache_size
        self.first_uncached_block = first_uncached_block
        self.block_size = self.storage.block_size
        return self

    def _get_block_range(self, offset, length, inner=False):
        """
        For inner=False: compute block range fully containing [offset, offset+length)
        For inner=True: compute block range fully contained in [offset, offset+length)
        """
        length = max(min(length, self.size - offset), 0)

        start_block, start_skip = divmod(offset, self.block_size)
        end_block, end_skip = divmod(offset + length, self.block_size)

        if inner:
            if start_skip > 0:
                start_block += 1
                start_skip = self.block_size - start_skip

            if offset + length == self.size and end_skip > 0:
                # the last block can be partial
                end_skip = 0
                end_block += 1
        else:
            if end_skip > 0:
                end_block += 1
                if offset + length == self.size:
                    # last block can be partial
                    end_skip = 0
                else:
                    end_skip = self.block_size - end_skip

        return start_block, end_block, start_skip, end_skip

    def _pad_file(self, new_size):
        """
        Append zero bytes that the virtual size grows to new_size
        """
        if new_size <= self.size:
            return

        # Fill remainder blocks in the file with nulls; the last
        # existing block, if partial, is implicitly null-padded
        start_block = _ceildiv(self.size, self.block_size)
        end_block = _ceildiv(new_size, self.block_size)

        for idx in range(start_block, end_block):
            self.storage[idx] = None

        self.size = new_size

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
            if offset + data_size >= self.cache_size:
                # last block can be partial
                end_block += 1
                end_skip = 0
            else:
                # not enough data
                return offset, data_list

        data = "".join(data_list)[start_skip:]

        if start_block < self.first_uncached_block:
            i = self.first_uncached_block - start_block
            start_block = self.first_uncached_block
        else:
            i = 0

        end_block = min(end_block, _ceildiv(self.cache_size, self.block_size))

        for j in xrange(start_block, end_block):
            if j not in self.storage:
                block = data[i*self.block_size:(i+1)*self.block_size]
                self.storage[j] = block
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
        return self.size

    def get_file(self):
        # Pad file to full size before returning file handle
        self._pad_file(self.get_size())
        return BlockCachedFileHandle(self)

    def close(self):
        self.storage.f.close()
        self.storage = None

    def truncate(self, size):
        if size < self.size:
            self.storage.truncate(_ceildiv(size, self.block_size))
            self.size = size
        elif size > self.size:
            self._pad_file(size)

        self.cache_size = min(self.cache_size, size)

    def write(self, offset, data):
        if offset > self.size:
            # Explicit POSIX behavior for write-past-end
            self._pad_file(offset)

        if len(data) == 0:
            # noop
            return

        # Sanity check cache status
        if self.pre_write(offset, len(data)) is not None:
            raise RuntimeError("attempt to write before caching")

        # Perform write
        start_block, start_pos = divmod(offset, self.block_size)
        end_block, end_pos = divmod(offset + len(data), self.block_size)
        if end_pos == 0 and end_block > start_block:
            end_block -= 1
            end_pos = self.block_size

        # Pad virtual size
        self._pad_file(offset + len(data))
        self.size = max(self.size, offset + len(data))

        # Write first block
        if start_pos == 0 and start_block != end_block:
            block = data[:self.block_size]
            i = len(block)
        else:
            block = self.storage[start_block]
            if end_block == start_block:
                i = len(data)
                if self.size == offset + len(data):
                    # Last block can be partial
                    block = block[:start_pos] + data
                else:
                    block = block[:start_pos] + data + block[end_pos:]
            else:
                i = self.block_size - start_pos
                block = block[:start_pos] + data[:i]
        self.storage[start_block] = block

        # Write intermediate blocks
        for idx in xrange(start_block + 1, end_block):
            self.storage[idx] = data[i:i+self.block_size]
            i += self.block_size

        # Write last block
        if start_block != end_block:
            if end_pos < self.block_size:
                block = self.storage[end_block]
                block = data[i:] + block[end_pos:]
                self.storage[end_block] = block
            else:
                self.storage[end_block] = data[i:]

    def read(self, offset, length):
        length = max(0, min(self.size - offset, length))
        if length == 0:
            return b''

        # Sanity check cache status
        if self.pre_read(offset, length) is not None:
            raise RuntimeError("attempt to read before caching")

        # Perform read
        start_block, start_pos = divmod(offset, self.block_size)
        end_block, end_pos = divmod(offset + length, self.block_size)
        if end_pos == 0 and end_block > start_block:
            end_block -= 1
            end_pos = self.block_size

        datas = []

        # Read first block
        block = self.storage[start_block]
        if end_block == start_block:
            datas.append(block[start_pos:end_pos])
        else:
            datas.append(block[start_pos:])

        # Read intermediate blocks
        for idx in xrange(start_block+1, end_block):
            datas.append(self.storage[idx])

        # Read last block
        if end_block != start_block:
            datas.append(self.storage[end_block][:end_pos])

        return b"".join(datas)

    def pre_read(self, offset, length):
        """
        Return (offset, length) of the first cache fetch that need to be
        performed and the results fed into `receive_cached_data` before a read
        operation can be performed. There may be more than one fetch
        necessary. Return None if no fetch is necessary.
        """
        start_block, end_block, _, _ = self._get_block_range(offset, length)
        end_block = min(end_block, _ceildiv(self.cache_size, self.block_size))

        # Combine consequent blocks into a single read
        j = max(start_block, self.first_uncached_block)
        while j < end_block and j in self.storage:
            j += 1
        if j >= end_block:
            return None

        for k in xrange(j+1, end_block):
            if k in self.storage:
                end = k
                break
        else:
            end = end_block

        if j >= end:
            return None

        start_pos = j * self.block_size
        end_pos = end * self.block_size
        if start_pos < self.cache_size:
            return (start_pos, min(end_pos, self.cache_size) - start_pos)

        return None

    def pre_write(self, offset, length):
        """
        Similarly to pre_read, but for write operations.
        """
        start_block, end_block, start_skip, end_skip = self._get_block_range(offset, length)

        if start_block < end_block:
            if (offset % self.block_size) != 0 and start_block not in self.storage:
                start_pos = start_block * self.block_size
                end_pos = (start_block + 1) * self.block_size
                if start_pos < self.cache_size:
                    return (start_pos, min(self.cache_size, end_pos) - start_pos)

            if ((offset + length) % self.block_size) != 0 and end_block-1 not in self.storage:
                start_pos = (end_block - 1) * self.block_size
                end_pos = end_block * self.block_size
                if start_pos < self.cache_size:
                    return (start_pos, min(self.cache_size, end_pos) - start_pos)

        # No reads required
        return None


class BlockCachedFileHandle(object):
    """
    Read-only access to BlockCachedFile, as if it was a contiguous file
    """
    def __init__(self, block_cached_file):
        self.block_cached_file = block_cached_file
        self.pos = 0

    def seek(self, offset, whence):
        if whence == 0:
            self.pos = offset
        elif whence == 1:
            self.pos += offset
        elif whence == 2:
            self.pos = offset + self.block_cached_file.get_size()
        else:
            raise ValueError("Invalid whence")

    def read(self, size):
        return self.block_cached_file.read(self.pos, size)
