"""
Cache metadata and data of a directory tree.
"""

import os
import sys
import time
import json
import struct
import errno
import threading

from Crypto.Hash import HMAC, SHA256, SHA512
from Crypto import Random
import pbkdf2

from tahoefuse.tahoeio import HTTPError, TahoeConnection
from tahoefuse.crypto import CryptFile, HKDF_SHA256_extract, HKDF_SHA256_expand
from tahoefuse.blockcache import BlockCachedFile


class CacheDB(object):
    def __init__(self, path, rootcap, node_url):
        if not os.path.isdir(path):
            raise IOError(errno.ENOENT, "Cache directory is not an existing directory")

        assert isinstance(rootcap, unicode)

        self.path = path
        self.prk = self._generate_prk(rootcap)

        # Cache lock
        self.lock = threading.RLock()

        # Open files and dirs
        self.open_items = {}

        # List of alive files
        self.alive_files = []

        # Load alive files
        self._load_alive_files()

        # Remove dead files
        self._cleanup()

    def _generate_prk(self, rootcap):
        # Cache master key is derived from hashed rootcap and salt via
        # PBKDF2, with a fixed number of iterations.
        #
        # The master key, combined with a second different salt, are
        # used to generate per-file keys via HKDF-SHA256

        # Get salt
        salt_fn = os.path.join(self.path, 'salt')
        try:
            with open(salt_fn, 'rb') as f:
                salt = f.read(32)
                salt_hkdf = f.read(32)
                if len(salt) != 32 or len(salt_hkdf) != 32:
                    raise ValueError()
        except (IOError, OSError, ValueError):
            # Start with new salt
            rnd = Random.new()
            salt = rnd.read(32)
            salt_hkdf = rnd.read(32)
            with open(salt_fn, 'wb') as f:
                f.write(salt)
                f.write(salt_hkdf)

        # Derive key
        d = pbkdf2.PBKDF2(passphrase=rootcap.encode('ascii'),
                          salt=salt,
                          iterations=100000,
                          digestmodule=SHA256)
        key = d.read(32)

        # HKDF private key material for per-file keys
        return HKDF_SHA256_extract(salt=salt_hkdf, key=key)

    def _load_alive_files(self):
        """
        Walk through the cached directory tree, and record in
        self.alive_files which cache files are reachable from the
        root.
        """
        self.alive_files = []

        stack = []

        # Start from root
        fn, key = self.get_filename_and_key(u"")
        if os.path.isfile(fn):
            stack.append((u"", fn, key))

        # Walk the tree
        while stack:
            upath, fn, key = stack.pop()

            if not os.path.isfile(fn):
                continue

            try:
                with CryptFile(fn, key=key, mode='rb') as f:
                    data = json.load(f)
                    if data[0] != u'dirnode':
                        raise ValueError()
                    children = data[1].get(u'children', {}).items()
            except (IOError, OSError, ValueError):
                continue

            self.alive_files.append((os.path.basename(fn), upath))

            for c_fn, c_info in children:
                c_upath = os.path.join(upath, c_fn)
                if c_info[0] == u'dirnode':
                    c_fn, c_key = self.get_filename_and_key(c_upath)
                    if os.path.isfile(c_fn):
                        stack.append((c_upath, c_fn, c_key))
                elif c_info[0] == u'filenode':
                    for ext in (None, b'state', b'data'):
                        c_fn, c_key = self.get_filename_and_key(c_upath, ext=ext)
                        self.alive_files.append((os.path.basename(c_fn), c_upath))

    def _cleanup(self):
        alive_file_set = set(x[0] for x in self.alive_files)
        for basename in os.listdir(self.path):
            if basename == 'salt':
                continue
            if basename not in alive_file_set:
                fn = os.path.join(self.path, basename)
                os.unlink(fn)

    def open_file(self, upath, io, flags):
        with self.lock:
            f = self.get_file(upath, io, creat=(flags & os.O_CREAT), excl=(flags & os.O_EXCL))
            return CachedFileHandle(upath, f, flags)

    def open_dir(self, upath, io):
        with self.lock:
            f = self.get_dir(upath, io)
            # CachedDir also serves as the handle
            return f

    def close_file(self, f):
        with self.lock:
            c = f.cached_file
            upath = f.upath
            f.close()
            if c.closed:
                del self.open_items[upath]

    def close_dir(self, f):
        with self.lock:
            c = f
            upath = f.upath
            f.close()
            if c.closed:
                del self.open_items[upath]

    def get_file(self, upath, io, creat=False, excl=False):
        with self.lock:
            f = self.open_items.get(upath)
            if f is None:
                f = CachedFile(self, upath, io, creat=creat, excl=excl)
                self.open_items[upath] = f
                return f
            else:
                if excl and f is not None:
                    raise IOError(errno.EEXIST, "file already exists")
                if not isinstance(f, CachedFile):
                    raise IOError(errno.EISDIR, "item is a directory")
                return f

    def get_dir(self, upath, io):
        with self.lock:
            f = self.open_items.get(upath)
            if f is None:
                f = CachedDir(self, upath, io)
                self.open_items[upath] = f
                return f
            else:
                if not isinstance(f, CachedDir):
                    raise IOError(errno.ENOTDIR, "item is a file")
                return f

    def get_upath_parent(self, path):
        return self.get_upath(os.path.dirname(os.path.normpath(path)))

    def get_upath(self, path):
        try:
            path = os.path.normpath(path)
            return path.decode(sys.getfilesystemencoding()).lstrip(u'/')
        except UnicodeError:
            raise IOError(errno.ENOENT, "file does not exist")

    def get_filename_and_key(self, upath, ext=None):
        path = upath.encode('utf-8')
        nonpath = b"//\x00" # cannot occur in path, which is normalized

        # Generate per-file key material via HKDF
        info = path
        if ext is not None:
            info += nonpath + ext
        data = HKDF_SHA256_expand(self.prk, info, 3*32)

        # Generate key
        key = data[:32]

        # Generate filename
        fn = HMAC.new(data[32:], msg=info, digestmod=SHA512).hexdigest()
        return os.path.join(self.path, fn), key


class CachedFileHandle(object):
    """
    Logical file handle. There may be multiple open file handles
    corresponding to the same logical file.
    """

    def __init__(self, upath, cached_file, flags):
        self.cached_file = cached_file
        self.cached_file.incref()
        self.lock = threading.RLock()
        self.flags = flags
        self.upath = upath

        self.writeable = (self.flags & (os.O_RDONLY | os.O_RDWR | os.O_WRONLY)) in (os.O_RDWR, os.O_WRONLY)
        self.readable = (self.flags & (os.O_RDONLY | os.O_RDWR | os.O_WRONLY)) in (os.O_RDWR, os.O_RDONLY)

        if self.flags & os.O_ASYNC:
            raise IOError(errno.EINVAL, "O_ASYNC flag is not supported")
        if self.flags & os.O_DIRECT:
            raise IOError(errno.EINVAL, "O_DIRECT flag is not supported")
        if self.flags & os.O_DIRECTORY:
            raise IOError(errno.EINVAL, "O_DIRECTORY flag is not supported")
        if self.flags & os.O_NOFOLLOW:
            raise IOError(errno.EINVAL, "O_NOFOLLOW flag is not supported")
        if self.flags & os.O_SYNC:
            raise IOError(errno.EINVAL, "O_SYNC flag is not supported")
        if (self.flags & os.O_CREAT) and not self.writeable:
            raise IOError(errno.EINVAL, "O_CREAT without writeable file")
        if (self.flags & os.O_TRUNC) and not self.writeable:
            raise IOError(errno.EINVAL, "O_TRUNC without writeable file")
        if (self.flags & os.O_EXCL) and not self.writeable:
            raise IOError(errno.EINVAL, "O_EXCL without writeable file")
        if self.flags & os.O_TRUNC:
            self.cached_file.truncate(0)

    def close(self):
        with self.lock:
            if self.cached_file is None:
                raise IOError(errno.EINVAL, "Operation on a closed file")
            c = self.cached_file
            self.cached_file = None
            c.decref()

    def truncate(self, size):
        with self.lock:
            if self.cached_file is None:
                raise IOError(errno.EINVAL, "Operation on a closed file")
            if not self.writeable:
                raise IOError(errno.EINVAL, "File not writeable")
            return self.cached_file.truncate(size)

    def read(self, io, offset, length):
        with self.lock:
            if self.cached_file is None:
                raise IOError(errno.EINVAL, "Operation on a closed file")
            if not self.readable:
                raise IOError(errno.EINVAL, "File not readable")
            return self.cached_file.read(io, offset, length)

    def write(self, io, offset, data):
        with self.lock:
            if self.cached_file is None:
                raise IOError(errno.EINVAL, "Operation on a closed file")
            if not self.writeable:
                raise IOError(errno.EINVAL, "File not writeable")
            if self.flags & os.O_APPEND:
                offset = self.cached_file.get_size()
            return self.cached_file.write(io, offset, data)

    def upload(self, io, upath):
        with self.lock:
            self.cached_file.upload(io, upath)


class CachedFile(object):
    """
    Logical file on-disk. Nameless (deleted) files have upath=None.
    There should be only a single CachedFile instance is per each logical file.
    """

    direct_io = False
    keep_cache = False

    def __init__(self, cachedb, upath, io, excl=False, creat=False):
        self.closed = False
        self.refcnt = 1

        # Use per-file keys for different files, for safer fallback
        # in the extremely unlikely event of SHA512 hash collisions
        filename, key = cachedb.get_filename_and_key(upath)
        filename_state, key_state = cachedb.get_filename_and_key(upath, b'state')
        filename_data, key_data = cachedb.get_filename_and_key(upath, b'data')

        self.lock = threading.RLock()
        self.dirty = False
        self.f = None
        self.f_state = None
        self.f_data = None

        open_ok = True

        # Reuse cached data
        try:
            self.f = CryptFile(filename, key=key, mode='r+b')
            self.info = json.load(self.f)

            self.f_state = CryptFile(filename_state, key=key_state, mode='r+b')
            self.f_data = CryptFile(filename_data, key=key_data, mode='r+b')
            self.block_cache = BlockCachedFile.restore_state(self.f_data, self.f_state)
        except (IOError, OSError, ValueError):
            open_ok = False
            if self.f is not None:
                self.f.close()
                self.f = None
            if self.f_state is not None:
                self.f_state.close()
            if self.f_data is not None:
                self.f_data.close()

        if open_ok and excl:
            raise IOError(errno.EEXIST, "file already exists")

        if not open_ok:
            self.f = CryptFile(filename, key=key, mode='w+b')

            try:
                self._load_info(upath, io)
                if excl:
                    raise IOError(errno.EEXIST, "file already exists")
            except IOError, err:
                if err.errno == errno.ENOENT and creat:
                    self.info = {}
                else:
                    os.unlink(filename)
                    self.f.close()
                    raise

            # Create a data file filled with random data
            self.f_data = CryptFile(filename_data, key=key_data, mode='w+b')
            self.f_data.write(RandomString(self.info[1][u'size']))

            # Block cache on top of data file
            self.block_cache = BlockCachedFile(self.f_data, self.info[1][u'size'])

            # Block data state file
            self.f_state = CryptFile(filename_state, key=key_state, mode='w+b')

    def _load_info(self, upath, io, iscap=False):
        try:
            self.info = io.get_info(upath, iscap=iscap)
        except (HTTPError, ValueError), err:
            if isinstance(err, HTTPError) and err.code == 404:
                raise IOError(errno.ENOENT, "no such file")
            raise IOError(errno.EFAULT, "failed to retrieve information")
        self.f.truncate(0)
        self.f.seek(0)
        json.dump(self.info, self.f)

    def incref(self):
        with self.lock:
            self.refcnt += 1

    def decref(self):
        with self.lock:
            self.refcnt -= 1
            if self.refcnt <= 0:
                self.close()

    def close(self):
        with self.lock:
            if not self.closed:
                self.f_state.seek(0)
                self.f_state.truncate(0)
                self.block_cache.save_state(self.f_state)
                self.f_state.close()
                self.block_cache.close()
                self.f.close()
            self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def _do_rw(self, io, offset, length_or_data, write=False, no_result=False):
        if write:
            data = length_or_data
            length = len(data)
        else:
            length = length_or_data

        stream_f = None
        stream_offset = 0
        stream_data = []

        try:
            while True:
                if write:
                    pos = self.block_cache.pre_write(offset, length)
                else:
                    pos = self.block_cache.pre_read(offset, length)

                if pos is None:
                    # cache ready
                    if no_result:
                        return None
                    elif write:
                        return self.block_cache.write(offset, data)
                    else:
                        return self.block_cache.read(offset, length)
                else:
                    # cache not ready -- fill it up
                    c_offset, c_length = pos

                    if stream_f is not None and (stream_offset < c_offset or c_offset > stream_offset + 10000):
                        stream_f.close()
                        stream_f = None

                    if stream_f is None:
                        stream_f = io.get_content(self.info[1][u'ro_uri'], c_offset, c_length, iscap=True)
                        stream_offset = c_offset
                        stream_data = []

                    read_offset = stream_offset
                    read_bytes = 0
                    while read_offset + read_bytes < c_length + c_offset:
                        block = stream_f.read(131072)
                        if not block:
                            stream_f.close()
                            stream_f = None
                            break

                        stream_data.append(block)
                        read_bytes += len(block)
                        stream_offset, stream_data = self.block_cache.receive_cached_data(stream_offset, stream_data)

        except HTTPError, err: 
            raise IOError(errno.EFAULT, "I/O error: %s" % (str(err),))
        finally:
            if stream_f is not None:
                stream_f.close()

    def _buffer_whole_file(self, io):
        self._do_rw(io, 0, self.block_cache.get_size(), write=False, no_result=True)

    def get_size(self):
        with self.lock:
            return self.block_cache.get_size()

    def read(self, io, offset, length):
        with self.lock:
            return self._do_rw(io, offset, length, write=False)

    def write(self, io, offset, data):
        with self.lock:
            if len(data) > 0:
                self.dirty = True
                self._do_rw(io, offset, data, write=True)

    def truncate(self, size):
        with self.lock:
            if size != self.block_cache.get_size():
                self.dirty = True
            self.block_cache.truncate(size)

    def upload(self, io, upath):
        with self.lock:
            if not self.dirty:
                # No changes
                return

            # Buffer all data
            self._buffer_whole_file(io)

            # Upload the whole file
            class Fwrapper(object):
                def __init__(self, block_cache):
                    self.block_cache = block_cache
                    self.size = block_cache.get_size()
                    self.f = self.block_cache.get_file()
                    self.f.seek(0)
                def __len__(self):
                    return self.size
                def read(self, size):
                    return self.f.read(size)

            fw = Fwrapper(self.block_cache)
            try:
                filecap = io.put_file(upath, fw)
            except HTTPError, err:
                raise IOError(errno.EFAULT, "I/O error: %s" % (str(err),))

            filecap = filecap.decode('latin1').strip()
            self._load_info(filecap, io, iscap=True)

            self.dirty = False


class CachedDir(object):
    """
    Logical file on-disk directory. Nameless (deleted) directories have upath=None.
    """

    def __init__(self, cachedb, upath, io):
        self.upath = upath
        self.closed = False

        filename, key = cachedb.get_filename_and_key(upath)
        try:
            with CryptFile(filename, key=key, mode='rb') as f:
                self.info = json.load(f)
            return
        except (IOError, OSError, ValueError):
            pass

        f = CryptFile(filename, key=key, mode='w+b')
        try:
            self.info = io.get_info(upath)
            json.dump(self.info, f)
        except (HTTPError, ValueError):
            os.unlink(filename)
            raise IOError(errno.EFAULT, "failed to retrieve information")
        finally:
            f.close()

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def listdir(self):
        return list(self.info[1][u'children'].keys())

    def get_attr(self):
        return dict(type='dir')

    def get_child_attr(self, childname):
        assert isinstance(childname, unicode)
        children = self.info[1][u'children']
        if childname not in children:
            raise IOError(errno.ENOENT, "no such entry")

        info = children[childname]
        if info[0] == u'dirnode':
            return dict(type='dir', 
                        ctime=info[1][u'metadata'][u'tahoe'][u'linkcrtime'],
                        mtime=info[1][u'metadata'][u'tahoe'][u'linkcrtime'])
        elif info[0] == u'filenode':
            return dict(type='file', 
                        size=info[1]['size'],
                        ctime=info[1][u'metadata'][u'tahoe'][u'linkcrtime'],
                        mtime=info[1][u'metadata'][u'tahoe'][u'linkcrtime'])
        else:
            raise IOError(errno.EBADF, "invalid entry")


class RandomString(object):
    def __init__(self, size):
        self._random = Random.new()
        self.size = size

    def __len__(self):
        return self.size

    def __getitem__(self, k):
        if isinstance(k, slice):
            return self._random.read(len(xrange(*k.indices(self.size))))
        else:
            raise IndexError("invalid index")
