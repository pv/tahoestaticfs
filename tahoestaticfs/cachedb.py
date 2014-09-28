"""
Cache metadata and data of a directory tree for read-only access.
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

from tahoestaticfs.tahoeio import HTTPError, TahoeConnection
from tahoestaticfs.crypto import CryptFile, HKDF_SHA256_extract, HKDF_SHA256_expand
from tahoestaticfs.blockcache import BlockCachedFile


class CacheDB(object):
    def __init__(self, path, rootcap, node_url, cache_size, cache_data):
        if not os.path.isdir(path):
            raise IOError(errno.ENOENT, "Cache directory is not an existing directory")

        assert isinstance(rootcap, unicode)

        self.cache_size = cache_size
        self.cache_data = cache_data

        self.path = path
        self.prk = self._generate_prk(rootcap)

        self.last_size_check_time = 0

        # Cache lock
        self.lock = threading.RLock()

        # Open files and dirs
        self.open_items = {}

        # Remove dead files
        with self.lock:
            self._cleanup()

        # Restrict cache size
        self._restrict_size()

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

    def _cleanup(self):
        """
        Walk through the cached directory tree, and remove files not
        reachable from the root.
        """
        alive_files = []

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

            alive_files.append((os.path.basename(fn), upath))

            for c_fn, c_info in children:
                c_upath = os.path.join(upath, c_fn)
                if c_info[0] == u'dirnode':
                    c_fn, c_key = self.get_filename_and_key(c_upath)
                    if os.path.isfile(c_fn):
                        stack.append((c_upath, c_fn, c_key))
                elif c_info[0] == u'filenode':
                    for ext in (None, b'state', b'data'):
                        c_fn, c_key = self.get_filename_and_key(c_upath, ext=ext)
                        alive_files.append((os.path.basename(c_fn), c_upath))

        alive_file_set = set(x[0] for x in alive_files)
        for basename in os.listdir(self.path):
            if basename == 'salt':
                continue
            fn = os.path.join(self.path, basename)
            if basename not in alive_file_set and os.path.isfile(fn):
                os.unlink(fn)

    def _restrict_size(self):
        def get_cache_score(entry):
            fn, st = entry
            return -cache_score(size=st.st_size, t=now-st.st_mtime)

        with self.lock:
            now = time.time()
            if now < self.last_size_check_time + 60:
                return

            self.last_size_check_time = now

            files = [os.path.join(self.path, fn) 
                     for fn in os.listdir(self.path) 
                     if fn != "salt"]
            entries = [(fn, os.stat(fn)) for fn in files]
            entries.sort(key=get_cache_score)

            tot_size = 0
            for fn, st in entries:
                if tot_size + st.st_size > self.cache_size:
                    # unlink
                    os.unlink(fn)
                else:
                    tot_size += st.st_size

    def open_file(self, upath, io, flags):
        with self.lock:
            f = self.get_file(upath, io)
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
                self._restrict_size()

    def close_dir(self, f):
        with self.lock:
            c = f
            upath = f.upath
            f.close()
            if c.closed:
                del self.open_items[upath]
                self._restrict_size()

    def _lookup_ro_cap(self, upath, io):
        with self.lock:
            if upath == u'':
                # root
                return None
            else:
                entry_name = os.path.basename(upath)
                parent_upath = os.path.dirname(upath)

                parent = self.open_dir(parent_upath, io)
                try:
                    return parent.get_child_attr(entry_name)['ro_uri']
                finally:
                    self.close_dir(parent)

    def get_file(self, upath, io):
        with self.lock:
            f = self.open_items.get(upath)
            if f is None:
                cap = self._lookup_ro_cap(upath, io)
                f = CachedFile(self, upath, io, filecap=cap)
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
                cap = self._lookup_ro_cap(upath, io)
                f = CachedDir(self, upath, io, dircap=cap)
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

    direct_io = False
    keep_cache = False

    def __init__(self, upath, cached_file, flags):
        self.cached_file = cached_file
        self.cached_file.incref()
        self.lock = threading.RLock()
        self.flags = flags
        self.upath = upath

        self.writeable = (self.flags & (os.O_RDONLY | os.O_RDWR | os.O_WRONLY)) in (os.O_RDWR, os.O_WRONLY)
        self.readable = (self.flags & (os.O_RDONLY | os.O_RDWR | os.O_WRONLY)) in (os.O_RDWR, os.O_RDONLY)

        if self.writeable:
            raise IOError(os.EACCESS, "read-only filesystem")
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

    def close(self):
        with self.lock:
            if self.cached_file is None:
                raise IOError(errno.EINVAL, "Operation on a closed file")
            c = self.cached_file
            self.cached_file = None
            c.decref()

    def read(self, io, offset, length):
        with self.lock:
            if self.cached_file is None:
                raise IOError(errno.EINVAL, "Operation on a closed file")
            if not self.readable:
                raise IOError(errno.EINVAL, "File not readable")
            return self.cached_file.read(io, offset, length)

    def get_size(self):
        with self.lock:
            return self.cached_file.get_size()


class CachedFile(object):
    """
    Logical file on-disk. There should be only a single CachedFile
    instance is per each logical file.
    """

    def __init__(self, cachedb, upath, io, filecap=None, persistent=False):
        self.closed = False
        self.refcnt = 0
        self.persistent = persistent

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

        self.stream_f = None
        self.stream_offset = 0
        self.stream_data = []

        open_complete = False

        try:
            # Reuse cached metadata
            self.f = CryptFile(filename, key=key, mode='r+b')
            self.info = json.load(self.f)

            if persistent:
                # Reuse cached data
                self.f_state = CryptFile(filename_state, key=key_state, mode='r+b')
                self.f_data = CryptFile(filename_data, key=key_data, mode='r+b')
                self.block_cache = BlockCachedFile.restore_state(self.f_data, self.f_state)
                open_complete = True
        except (IOError, OSError, ValueError):
            open_complete = False
            if self.f is not None:
                self.f.close()
                self.f = None
            if self.f_state is not None:
                self.f_state.close()
            if self.f_data is not None:
                self.f_data.close()

        if not open_complete:
            if self.f is None:
                self.f = CryptFile(filename, key=key, mode='w+b')
                try:
                    if filecap is not None:
                        self._load_info(filecap, io, iscap=True)
                    else:
                        self._load_info(upath, io)
                except IOError, err:
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

        os.utime(self.f.path, None)
        os.utime(self.f_data.path, None)
        os.utime(self.f_state.path, None)

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
                if self.stream_f is not None:
                    self.stream_f.close()
                    self.stream_f = None
                    self.stream_data = []
                self.f_state.seek(0)
                self.f_state.truncate(0)
                self.block_cache.save_state(self.f_state)
                self.f_state.close()
                self.block_cache.close()
                self.f.close()

                if not self.persistent:
                    os.unlink(self.f_state.path)
                    os.unlink(self.f_data.path)
            self.closed = True

    def _do_rw(self, io, offset, length_or_data, write=False, no_result=False):
        if write:
            data = length_or_data
            length = len(data)
        else:
            length = length_or_data

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

                    if self.stream_f is not None and (self.stream_offset < c_offset or 
                                                      c_offset > self.stream_offset + 10000):
                        self.stream_f.close()
                        self.stream_f = None
                        self.stream_data = []

                    if self.stream_f is None:
                        self.stream_f = io.get_content(self.info[1][u'ro_uri'], c_offset, iscap=True)
                        self.stream_offset = c_offset
                        self.stream_data = []

                    read_offset = self.stream_offset
                    read_bytes = 0
                    while read_offset + read_bytes < c_length + c_offset:
                        block = self.stream_f.read(131072)
                        if not block:
                            self.stream_f.close()
                            self.stream_f = None
                            self.stream_data = []
                            break

                        self.stream_data.append(block)
                        read_bytes += len(block)
                        self.stream_offset, self.stream_data = self.block_cache.receive_cached_data(
                            self.stream_offset, self.stream_data)

        except HTTPError, err: 
            if self.stream_f is not None:
                self.stream_f.close()
            self.stream_f = None
            raise IOError(errno.EFAULT, "I/O error: %s" % (str(err),))

    def get_size(self):
        with self.lock:
            return self.block_cache.get_size()

    def read(self, io, offset, length):
        with self.lock:
            return self._do_rw(io, offset, length, write=False)


class CachedDir(object):
    """
    Logical file on-disk directory.
    """

    def __init__(self, cachedb, upath, io, dircap=None):
        self.upath = upath
        self.closed = False

        filename, key = cachedb.get_filename_and_key(upath)
        try:
            with CryptFile(filename, key=key, mode='rb') as f:
                self.info = json.load(f)
            os.utime(filename, None)
            return
        except (IOError, OSError, ValueError):
            pass

        f = CryptFile(filename, key=key, mode='w+b')
        try:
            if dircap is not None:
                self.info = io.get_info(dircap, iscap=True)
            else:
                self.info = io.get_info(upath)
            json.dump(self.info, f)
        except (HTTPError, ValueError):
            os.unlink(filename)
            raise IOError(errno.EFAULT, "failed to retrieve information")
        finally:
            f.close()

        self.filename = filename

    def close(self):
        pass

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
                        ro_uri=info[1][u'ro_uri'],
                        ctime=info[1][u'metadata'][u'tahoe'][u'linkcrtime'],
                        mtime=info[1][u'metadata'][u'tahoe'][u'linkcrtime'])
        elif info[0] == u'filenode':
            return dict(type='file',
                        size=info[1][u'size'],
                        ro_uri=info[1][u'ro_uri'],
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



# constants for cache score calculation
_DOWNLOAD_SPEED = 1e6  # byte/sec
_LATENCY = 1.0 # sec

def _access_rate(size, t):
    """Return estimated access rate (unit 1/sec). `t` is time since last access"""
    if t < 0:
        return 0.0
    size_unit = 100e3
    size_prob = 1 / (1 + (size/size_unit)**2)
    return size_prob / (_LATENCY + t)

def cache_score(size, t):
    """
    Return cache score for file with size `size` and time since last access `t`.
    Bigger number means higher priority.
    """

    # Estimate how often it is downloaded
    rate = _access_rate(size, t)

    # Time cost for re-retrieval
    return rate * (_LATENCY + size / _DOWNLOAD_SPEED)
