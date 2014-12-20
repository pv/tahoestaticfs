"""
Cache metadata and data of a directory tree.
"""

import os
import sys
import struct
import errno
import fcntl

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

backend = default_backend()

BLOCK_SIZE = 131072


class CryptFile(object):
    """
    File encrypted with a key in AES-CBC mode, in BLOCK_SIZE blocks,
    with random IV for each block.
    """

    IV_SIZE = 16
    HEADER_SIZE = 8

    def __init__(self, path, key, mode='r+b', block_size=BLOCK_SIZE):
        self.key = None
        self.path = path

        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")

        if mode == 'rb':
            fd = os.open(path, os.O_RDONLY)
        elif mode == 'r+b':
            fd = os.open(path, os.O_RDWR)
        elif mode == 'w+b':
            fd = os.open(path, os.O_RDWR | os.O_CREAT, 00600)
        else:
            raise IOError(errno.EACCES, "Unsupported mode %r" % (mode,))

        try:
            # BSD locking on the file; only one fd can write at a time
            if mode == 'rb':
                fcntl.flock(fd, fcntl.LOCK_SH)
            else:
                fcntl.flock(fd, fcntl.LOCK_EX)

            if mode == 'w+b':
                # Truncate after locking
                os.ftruncate(fd, 0)

            self.fp = os.fdopen(fd, mode)
        except:
            os.close(fd)
            raise

        self.mode = mode
        self.key = key

        assert algorithms.AES.block_size//8 == 16

        if block_size % 16 != 0:
            raise ValueError("Block size must be multiple of AES block size")
        self.block_size = block_size

        if mode == 'w+b':
            self.data_size = 0
        else:
            try:
                sz = self.fp.read(8)
                self.data_size = struct.unpack('<Q', sz)[0]
            except (IOError, struct.error):
                self.fp.close()
                raise ValueError("invalid data in file")

        self.current_block = -1
        self.block_cache = b""
        self.block_dirty = False

        self.offset = 0

    def _flush_block(self):
        if self.current_block < 0:
            return
        if not self.block_dirty:
            return

        iv = os.urandom(self.IV_SIZE)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()

        self.fp.seek(self.HEADER_SIZE + self.current_block * (self.IV_SIZE + self.block_size))
        self.fp.write(iv)

        off = (len(self.block_cache) % 16)
        if off == 0:
            self.fp.write(encryptor.update(bytes(self.block_cache)))
        else:
            # insert random padding
            self.fp.write(encryptor.update(bytes(self.block_cache) + os.urandom(16-off)))
        self.fp.write(encryptor.finalize())

        self.block_dirty = False

    def _load_block(self, i):
        if i == self.current_block:
            return

        self._flush_block()

        self.fp.seek(self.HEADER_SIZE + i * (self.IV_SIZE + self.block_size))
        iv = self.fp.read(self.IV_SIZE)

        if not iv:
            # Block does not exist, past end of file
            self.current_block = i
            self.block_cache = b""
            self.block_dirty = False
            return

        ciphertext = self.fp.read(self.block_size)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()

        if (i+1)*self.block_size > self.data_size:
            size = self.data_size - i*self.block_size
        else:
            size = self.block_size

        self.current_block = i
        self.block_cache = (decryptor.update(ciphertext) + decryptor.finalize())[:size]
        self.block_dirty = False

    def seek(self, offset, whence=0):
        if whence == 0:
            pass
        elif whence == 1:
            offset = self.offset + offset
        elif whence == 2:
            offset += self.data_size
        else:
            raise IOError(errno.EINVAL, "Invalid whence")
        if offset < 0:
            raise IOError(errno.EINVAL, "Invalid offset")
        self.offset = offset

    def tell(self):
        return self.offset

    def _get_file_size(self):
        self.fp.seek(0, 2)
        return self.fp.tell()

    def _read(self, size, offset):
        if size is None:
            size = self.data_size - offset
        if size <= 0:
            return b""

        start_block, start_off = divmod(offset, self.block_size)
        end_block, end_off = divmod(offset + size, self.block_size)
        if end_off != 0:
            end_block += 1

        # Read and decrypt data
        data = []
        for i in range(start_block, end_block):
            self._load_block(i)
            data.append(self.block_cache)

        if end_off != 0:
            data[-1] = data[-1][:end_off]
        data[0] = data[0][start_off:]
        return b"".join(map(bytes, data))

    def _write(self, data, offset):
        size = len(data)
        start_block, start_off = divmod(offset, self.block_size)
        end_block, end_off = divmod(offset + size, self.block_size)

        k = 0

        if self.mode == 'rb':
            raise IOError(errno.EACCES, "Write to a read-only file")

        # Write first block, if partial
        if start_off != 0 or end_block == start_block:
            self._load_block(start_block)
            data_block = data[:(self.block_size - start_off)]
            self.block_cache = self.block_cache[:start_off] + data_block + self.block_cache[start_off+len(data_block):]
            self.block_dirty = True
            k += 1
            start_block += 1

        # Write full blocks
        for i in range(start_block, end_block):
            self._flush_block()
            self.current_block = i
            self.block_cache = data[k*self.block_size-start_off:(k+1)*self.block_size-start_off]
            self.block_dirty = True
            k += 1

        # Write last partial block
        if end_block > start_block and end_off != 0:
            self._load_block(end_block)
            data_block = data[k*self.block_size-start_off:(k+1)*self.block_size-start_off]
            self.block_cache = data_block + self.block_cache[len(data_block):]
            self.block_dirty = True

        self.data_size = max(self.data_size, offset + len(data))

    def read(self, size=None):
        data = self._read(size, self.offset)
        self.offset += len(data)
        return data

    def write(self, data):
        if self.data_size < self.offset:
            # Write past end
            s = NullString(self.offset - self.data_size)
            self._write(s, self.data_size)

        self._write(data, self.offset)
        self.offset += len(data)

    def truncate(self, size):
        last_block, last_off = divmod(size, self.block_size)

        self._load_block(last_block)
        last_block_data = self.block_cache

        # truncate to block boundary
        self._flush_block()
        sz = self.HEADER_SIZE + last_block * (self.IV_SIZE + self.block_size)
        self.fp.truncate(sz)
        self.data_size = last_block * self.block_size
        self.current_block = -1
        self.block_cache = b""
        self.block_dirty = False

        # rewrite the last block
        if last_off != 0:
            self._write(last_block_data[:last_off], self.data_size)

        # add null padding
        if self.data_size < size:
            s = NullString(size - self.data_size)
            self._write(s, self.data_size)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def flush(self):
        if self.mode != 'rb':
            self._flush_block()
            self.fp.seek(0)
            self.fp.write(struct.pack("<Q", self.data_size))
        self.fp.flush()

    def close(self):
        if self.key is None:
            return
        if self.mode != 'rb':
            self.flush()
        self.fp.close()
        self.key = None

    def __del__(self):
        self.close()


class NullString(object):
    def __init__(self, size):
        self.size = size

    def __len__(self):
        return self.size

    def __getitem__(self, k):
        if isinstance(k, slice):
            return b"\x00" * len(xrange(*k.indices(self.size)))
        else:
            raise IndexError("invalid index")
