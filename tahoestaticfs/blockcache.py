import struct
import errno
import array
import heapq
import itertools


BLOCK_SIZE = 131072
BLOCK_UNALLOCATED = -1
BLOCK_ZERO = -2


def ceildiv(a, b):
    """Compute ceil(a/b); i.e. rounded towards positive infinity"""
    return 1 + (a-1)//b


class BlockStorage(object):
    """
    File storing fixed-size blocks of data.
    """

    def __init__(self, f, block_size):
        self.f = f
        self.block_size = block_size
        self.block_map = array.array('l')
        self.zero_block = b"\x00"*self.block_size
        self._reconstruct_free_map()

    def save_state(self, f):
        f.truncate(0)
        f.seek(0)
        f.write(b"BLK2")
        f.write(struct.pack('<Qq', self.block_size, len(self.block_map)))
        f.write(self.block_map.tostring())

    @classmethod
    def restore_state(cls, f, state_file):
        hdr = state_file.read(4)
        if hdr != b"BLK2":
            raise ValueError("invalid block storage state file")
        s = state_file.read(2 * 8)
        block_size, num_blocks = struct.unpack('<Qq', s)

        block_map = array.array('l')
        s = state_file.read(num_blocks * block_map.itemsize)
        block_map.fromstring(s)

        self = cls.__new__(cls)
        self.f = f
        self.block_size = block_size
        self.block_map = block_map
        self.zero_block = b"\x00"*self.block_size
        self._reconstruct_free_map()
        return self

    def _reconstruct_free_map(self):
        if self.block_map:
            max_block = max(self.block_map)
        else:
            max_block = -1

        if max_block < 0:
            self.free_block_idx = 0
            self.free_map = []
            return

        mask = array.array('b', itertools.repeat(0, max_block+1))
        for x in self.block_map:
            if x >= 0:
                mask[x] = 1

        free_map = [j for j, x in enumerate(mask) if x == 0]
        heapq.heapify(free_map)

        self.free_map = free_map
        self.free_block_idx = max_block + 1

    def _get_free_block_idx(self):
        if self.free_map:
            return heapq.heappop(self.free_map)
        idx = self.free_block_idx
        self.free_block_idx += 1
        return idx

    def _add_free_block_idx(self, idx):
        heapq.heappush(self.free_map, idx)

    def _truncate_free_map(self, end_block):
        self.free_block_idx = end_block
        last_map_size = len(self.free_map)
        self.free_map = [x for x in self.free_map if x < end_block]
        if last_map_size != len(self.free_map):
            heapq.heapify(self.free_map)

    def __contains__(self, idx):
        if not idx >= 0:
            raise ValueError("Invalid block index")
        if idx >= len(self.block_map):
            return False
        return self.block_map[idx] != BLOCK_UNALLOCATED

    def __getitem__(self, idx):
        if idx not in self:
            raise KeyError("Block %d not allocated" % (idx,))

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
            self.block_map.extend(itertools.repeat(BLOCK_UNALLOCATED, idx + 1 - len(self.block_map)))

        if data is None or data == self.zero_block:
            block_idx = self.block_map[idx]
            if block_idx >= 0:
                self._add_free_block_idx(block_idx)
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

        end_block = 0
        if self.block_map:
            end_block = max(0, max(self.block_map) + 1)
        self.f.truncate(self.block_size * end_block)
        self._truncate_free_map(end_block)


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

    def _pad_file(self, new_size):
        """
        Append zero bytes that the virtual size grows to new_size
        """
        if new_size <= self.size:
            return

        # Fill remainder blocks in the file with nulls; the last
        # existing block, if partial, is implicitly null-padded
        start, mid, end = block_range(self.size, new_size - self.size, block_size=self.block_size)

        if start is not None and start[1] == 0:
            self.storage[start[0]] = None

        if mid is not None:
            for idx in range(*mid):
                self.storage[idx] = None

        if end is not None:
            self.storage[end[0]] = None

        self.size = new_size

    def receive_cached_data(self, offset, data_list):
        """
        Write full data blocks to file, unless they were not written
        yet. Returns (new_offset, new_data_list) containing unused,
        possibly reuseable data. data_list is a list of strings.
        """
        data_size = sum(len(data) for data in data_list)

        start, mid, end = block_range(offset, data_size, last_pos=self.cache_size,
                                      block_size=self.block_size)

        if mid is None:
            # not enough data for full blocks
            return offset, data_list

        data = "".join(data_list)

        i = 0
        if start is not None:
            # skip initial part
            i = self.block_size - start[1]

        for j in xrange(*mid):
            if j not in self.storage:
                block = data[i:i+self.block_size]
                self.storage[j] = block
            i += min(self.block_size, data_size - i)

        if mid[0] <= self.first_uncached_block:
            self.first_uncached_block = max(self.first_uncached_block, mid[1])

        # Return trailing data for possible future use
        if i < data_size:
            data_list = [data[i:]]
        else:
            data_list = []
        offset += i
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
            self.storage.truncate(ceildiv(size, self.block_size))
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

        # Perform write
        start, mid, end = block_range(offset, len(data), block_size=self.block_size)

        # Pad virtual size
        self._pad_file(offset + len(data))

        # Write first block
        if start is not None:
            block = self.storage[start[0]]
            i = start[2] - start[1]
            self.storage[start[0]] = block[:start[1]] + data[:i] + block[start[2]:]
        else:
            i = 0

        # Write intermediate blocks
        if mid is not None:
            for idx in xrange(*mid):
                self.storage[idx] = data[i:i+self.block_size]
                i += self.block_size

        # Write last block
        if end is not None:
            block = self.storage[end[0]]
            self.storage[end[0]] = data[i:] + block[end[1]:]

    def read(self, offset, length):
        length = max(0, min(self.size - offset, length))
        if length == 0:
            return b''

        # Perform read
        start, mid, end = block_range(offset, length, block_size=self.block_size)

        datas = []

        # Read first block
        if start is not None:
            datas.append(self.storage[start[0]][start[1]:start[2]])

        # Read intermediate blocks
        if mid is not None:
            for idx in xrange(*mid):
                datas.append(self.storage[idx])

        # Read last block
        if end is not None:
            datas.append(self.storage[end[0]][:end[1]])

        return b"".join(datas)

    def pre_read(self, offset, length):
        """
        Return (offset, length) of the first cache fetch that need to be
        performed and the results fed into `receive_cached_data` before a read
        operation can be performed. There may be more than one fetch
        necessary. Return None if no fetch is necessary.
        """

        # Limit to inside the cached area
        cache_end = ceildiv(self.cache_size, self.block_size) * self.block_size
        length = max(0, min(length, cache_end - offset))
        if length == 0:
            return None

        # Find bounds of the read operation
        start_block = offset//self.block_size
        end_block = ceildiv(offset + length, self.block_size)

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
        start, mid, end = block_range(offset, length, block_size=self.block_size)

        # Writes only need partially available blocks to be in the cache
        for item in (start, end):
            if item is not None and item[0] >= self.first_uncached_block and item[0] not in self.storage:
                start_pos = item[0] * self.block_size
                end_pos = (item[0] + 1) * self.block_size
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

    def seek(self, offset, whence=0):
        if whence == 0:
            self.pos = offset
        elif whence == 1:
            self.pos += offset
        elif whence == 2:
            self.pos = offset + self.block_cached_file.get_size()
        else:
            raise ValueError("Invalid whence")

    def read(self, size=None):
        if size is None:
            size = max(0, self.block_cached_file.get_size() - self.pos)
        data = self.block_cached_file.read(self.pos, size)
        self.pos += len(data)
        return data


def block_range(offset, length, block_size, last_pos=None):
    """
    Get the blocks that overlap with data range [offset, offset+length]

    Parameters
    ----------
    offset, length : int
        Range specification
    last_pos : int, optional
        End-of-file position. If the data range goes over the end of the file,
        the last block is the last block in `mid`, and `end` is None.

    Returns
    -------
    start : (idx, start_pos, end_pos) or None
        Partial block at the beginning; block[start_pos:end_pos] has the data. If missing: None
    mid : (start_idx, end_idx)
        Range [start_idx, end_idx) of full blocks in the middle. If missing: None
    end : (idx, end_pos)
        Partial block at the end; block[:end_pos] has the data. If missing: None

    """
    if last_pos is not None:
        length = max(min(last_pos - offset, length), 0)

    if length == 0:
        return None, None, None

    start_block, start_pos = divmod(offset, block_size)
    end_block, end_pos = divmod(offset + length, block_size)

    if last_pos is not None:
        if offset + length == last_pos and end_pos > 0:
            end_block += 1
            end_pos = 0

    if start_block == end_block:
        if start_pos == end_pos:
            return None, None, None
        return (start_block, start_pos, end_pos), None, None

    mid = None

    if start_pos == 0:
        start = None
        mid = (start_block, end_block)
    else:
        start = (start_block, start_pos, block_size)
        if start_block+1 < end_block:
            mid = (start_block+1, end_block)

    if end_pos == 0:
        end = None
    else:
        end = (end_block, end_pos)

    return start, mid, end
