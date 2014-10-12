"""
Cache metadata and data of a directory tree for read-only access.
"""

import os
import sys
import time
import json
import zlib
import struct
import errno
import threading
import heapq

from Crypto.Hash import HMAC, SHA512
from M2Crypto.EVP import pbkdf2

from tahoestaticfs.tahoeio import HTTPError
from tahoestaticfs.crypto import CryptFile, HKDF_SHA256_extract, HKDF_SHA256_expand
from tahoestaticfs.blockcache import BlockCachedFile


class CacheDB(object):
    def __init__(self, path, rootcap, node_url, cache_size, cache_data):
        path = os.path.abspath(path)
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

        # Directory cache
        self._max_item_cache = 500
        self._item_cache = []

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
                numiter = f.read(4)
                salt = f.read(32)
                salt_hkdf = f.read(32)
                if len(numiter) != 4 or len(salt) != 32 or len(salt_hkdf) != 32:
                    raise ValueError()
                numiter = struct.unpack('<I', numiter)[0]
        except (IOError, OSError, ValueError):
            # Start with new salt
            rnd = os.urandom(64)
            salt = rnd[:32]
            salt_hkdf = rnd[32:]

            # Determine suitable number of iterations
            start = time.time()
            count = 0
            while True:
                pbkdf2(password="a"*len(rootcap.encode('ascii')),
                       salt="b"*len(salt),
                       iter=1000,
                       keylen=32)
                count += 1000
                if time.time() > start + 0.05:
                    break
            numiter = max(10000, int(count * 1.0 / (time.time() - start)))

            # Write salt etc.
            with open(salt_fn, 'wb') as f:
                f.write(struct.pack('<I', numiter))
                f.write(salt)
                f.write(salt_hkdf)

        # Derive key
        key = pbkdf2(password=rootcap.encode('ascii'),
                     salt=salt,
                     iter=numiter,
                     keylen=32)

        # HKDF private key material for per-file keys
        return HKDF_SHA256_extract(salt=salt_hkdf, key=key)

    def _walk_cache_subtree(self, root_upath=u""):
        """
        Walk through items in the cached directory tree, starting from
        the given root point.

        Yields
        ------
        filename, upath
            Filename and corresponding upath of a reached cached entry.

        """
        stack = []

        # Start from root
        fn, key = self.get_filename_and_key(root_upath)
        if os.path.isfile(fn):
            stack.append((root_upath, fn, key))

        # Walk the tree
        while stack:
            upath, fn, key = stack.pop()

            if not os.path.isfile(fn):
                continue

            try:
                with CryptFile(fn, key=key, mode='rb') as f:
                    data = json_zlib_load(f)
                    if data[0] == u'dirnode':
                        children = data[1].get(u'children', {}).items()
                    else:
                        children = []
            except (IOError, OSError, ValueError):
                continue

            yield (os.path.basename(fn), upath)

            for c_fn, c_info in children:
                c_upath = os.path.join(upath, c_fn)
                if c_info[0] == u'dirnode':
                    c_fn, c_key = self.get_filename_and_key(c_upath)
                    if os.path.isfile(c_fn):
                        stack.append((c_upath, c_fn, c_key))
                elif c_info[0] == u'filenode':
                    for ext in (None, b'state', b'data'):
                        c_fn, c_key = self.get_filename_and_key(c_upath, ext=ext)
                        yield (os.path.basename(c_fn), c_upath)

    def _cleanup(self):
        """
        Walk through the cached directory tree, and remove files not
        reachable from the root.
        """
        alive_file_set = set()
        for fn, upath in self._walk_cache_subtree():
            alive_file_set.add(fn)

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

    def _invalidate(self, root_upath=u"", shallow=False):
        if root_upath == u"" and not shallow:
            for f in self.open_items.itervalues():
                f.invalidated = True
            self.open_items = {}
            dead_file_set = os.listdir(self.path)
        else:
            dead_file_set = set()
            for fn, upath in self._walk_cache_subtree(root_upath):
                f = self.open_items.pop(upath, None)
                if f is not None:
                    f.invalidated = True
                dead_file_set.add(fn)
                if shallow and upath != root_upath:
                    break

        for basename in dead_file_set:
            if basename == 'salt':
                continue
            fn = os.path.join(self.path, basename)
            if os.path.isfile(fn):
                os.unlink(fn)

    def invalidate(self, root_upath=u"", shallow=False):
        with self.lock:
            self._invalidate(root_upath, shallow=shallow)

    def open_file(self, upath, io, flags):
        with self.lock:
            writeable = (flags & (os.O_RDONLY | os.O_RDWR | os.O_WRONLY)) in (os.O_RDWR, os.O_WRONLY)
            if writeable:
                # Drop file data cache before opening in write mode
                if upath not in self.open_items:
                    self.invalidate(upath)

            f = self.get_file_inode(upath, io,
                                    excl=(flags & os.O_EXCL),
                                    creat=(flags & os.O_CREAT))
            return CachedFileHandle(upath, f, flags)

    def open_dir(self, upath, io):
        with self.lock:
            f = self.get_dir_inode(upath, io)
            return CachedDirHandle(upath, f)

    def close_file(self, f):
        with self.lock:
            c = f.inode
            upath = f.upath
            f.close()
            if c.closed:
                if upath in self.open_items:
                    del self.open_items[upath]
                self._restrict_size()

    def close_dir(self, f):
        with self.lock:
            c = f.inode
            upath = f.upath
            f.close()
            if c.closed:
                if upath in self.open_items:
                    del self.open_items[upath]
                self._restrict_size()

    def upload_file(self, c, io):
        if isinstance(c, CachedFileHandle):
            c = c.inode

        if c.upath is not None and c.dirty:
            parent_cap = self._lookup_cap(udirname(c.upath), io, read_only=False)
            c.upload(io, parent_cap=parent_cap)
            self.invalidate(udirname(c.upath), shallow=True)

    def unlink(self, upath, io, is_dir=False):
        if upath == u'':
            raise IOError(errno.EACCES, "cannot unlink root directory")

        with self.lock:
            # Invalidate cache
            if is_dir:
                f = self.open_dir(upath, io)
            else:
                f = self.open_file(upath, io, 0)
            try:
                f.inode.unlink()
            finally:
                if is_dir:
                    self.close_dir(f)
                else:
                    self.close_file(f)

            self.invalidate(udirname(upath), shallow=True)

            # Perform unlink
            try:
                cap = io.delete(upath)
            except HTTPError, err:
                if err.code == 404:
                    raise IOError(errno.ENOENT, "no such file")
                raise IOError(errno.EREMOTEIO, "failed to retrieve information")

    def mkdir(self, upath, io):
        if upath == u'':
            raise IOError(errno.EEXIST, "cannot re-mkdir root directory")

        with self.lock:
            # Check that parent exists
            f = self.open_dir(udirname(upath), io)
            parent_cap = f.inode.info[1][u'rw_uri']
            self.close_dir(f)

            # Check that the target does not exist
            try:
                f = self.open_dir(upath, io)
            except IOError, err:
                if err.errno == errno.ENOENT:
                    pass
                else:
                    raise
            else:
                self.close_dir(f)
                raise IOError(errno.EEXIST, "directory already exists")

            # Invalidate cache
            self.invalidate(upath)
            self.invalidate(udirname(upath), shallow=True)

            # Perform operation
            upath = parent_cap + u'/' + ubasename(upath)
            try:
                cap = io.mkdir(upath, iscap=True)
            except HTTPError, err:
                raise IOError(err.EREMOTEIO, "remote operation failed")

    def get_attr(self, upath, io):
        with self.lock:
            if upath == u'':
                dir = self.open_dir(upath, io)
                try:
                    info = dir.get_attr()
                finally:
                    self.close_dir(dir)
            else:
                upath_parent = udirname(upath)
                dir = self.open_dir(upath_parent, io)
                try:
                    info = dir.get_child_attr(ubasename(upath))
                except IOError, err:
                    if err.errno == errno.ENOENT and upath in self.open_items:
                        # New file that has not yet been uploaded
                        info = {}
                    else:
                        raise
                finally:
                    self.close_dir(dir)

            if upath in self.open_items:
                info.update(self.open_items[upath].get_attr())
                if 'mtime' not in info:
                    info['mtime'] = time.time()
                if 'ctime' not in info:
                    info['ctime'] = time.time()

            return info

    def _lookup_cap(self, upath, io, read_only=True):
        with self.lock:
            if upath in self.open_items:
                # shortcut
                try:
                    if read_only:
                        return self.open_items[upath].info[1][u'ro_uri']
                    else:
                        return self.open_items[upath].info[1][u'rw_uri']
                except:
                    print upath
                    print self.open_items[upath].info[1]
                    raise
            elif upath == u'':
                # root
                return None
            else:
                # lookup from parent
                entry_name = ubasename(upath)
                parent_upath = udirname(upath)

                parent = self.open_dir(parent_upath, io)
                try:
                    if read_only:
                        return parent.get_child_attr(entry_name)['ro_uri']
                    else:
                        return parent.get_child_attr(entry_name)['rw_uri']
                finally:
                    self.close_dir(parent)

    def get_file_inode(self, upath, io, excl=False, creat=False):
        with self.lock:
            f = self.open_items.get(upath)
            if f is None:
                try:
                    cap = self._lookup_cap(upath, io)
                except IOError, err:
                    if err.errno == errno.ENOENT and creat:
                        cap = None
                    else:
                        raise

                if excl and cap is not None:
                    raise IOError(errno.EEXIST, "file already exists")
                if not creat and cap is None:
                    raise IOError(errno.ENOENT, "file does not exist")

                f = CachedFileInode(self, upath, io, filecap=cap, 
                                    persistent=self.cache_data)
                self.open_items[upath] = f
                return f
            else:
                if excl:
                    raise IOError(errno.EEXIST, "file already exists")
                if not isinstance(f, CachedFileInode):
                    raise IOError(errno.EISDIR, "item is a directory")
                return f

    def get_dir_inode(self, upath, io):
        with self.lock:
            f = self.open_items.get(upath)
            if f is None:
                cap = self._lookup_cap(upath, io, read_only=False)
                f = CachedDirInode(self, upath, io, dircap=cap)
                self.open_items[upath] = f

                # Add to item cache
                cache_item = (time.time(), CachedDirHandle(upath, f))
                if len(self._item_cache) < self._max_item_cache:
                    heapq.heappush(self._item_cache, cache_item)
                else:
                    old_time, old_fh = heapq.heapreplace(self._item_cache,
                                                         cache_item)
                    self.close_dir(old_fh)

                return f
            else:
                if not isinstance(f, CachedDirInode):
                    raise IOError(errno.ENOTDIR, "item is a file")
                return f

    def get_upath_parent(self, path):
        return self.get_upath(os.path.dirname(os.path.normpath(path)))

    def get_upath(self, path):
        try:
            path = os.path.normpath(path)
            return path.decode(sys.getfilesystemencoding().replace(os.sep, "/")).lstrip(u'/')
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

    def __init__(self, upath, inode, flags):
        self.inode = inode
        self.inode.incref()
        self.lock = threading.RLock()
        self.flags = flags
        self.upath = upath

        self.writeable = (self.flags & (os.O_RDONLY | os.O_RDWR | os.O_WRONLY)) in (os.O_RDWR, os.O_WRONLY)
        self.readable = (self.flags & (os.O_RDONLY | os.O_RDWR | os.O_WRONLY)) in (os.O_RDWR, os.O_RDONLY)
        self.append = (self.flags & os.O_APPEND)

        if self.flags & os.O_ASYNC:
            raise IOError(errno.ENOTSUP, "O_ASYNC flag is not supported")
        if self.flags & os.O_DIRECT:
            raise IOError(errno.ENOTSUP, "O_DIRECT flag is not supported")
        if self.flags & os.O_DIRECTORY:
            raise IOError(errno.ENOTSUP, "O_DIRECTORY flag is not supported")
        if self.flags & os.O_SYNC:
            raise IOError(errno.ENOTSUP, "O_SYNC flag is not supported")
        if (self.flags & os.O_CREAT) and not self.writeable:
            raise IOError(errno.EINVAL, "O_CREAT without writeable file")
        if (self.flags & os.O_TRUNC) and not self.writeable:
            raise IOError(errno.EINVAL, "O_TRUNC without writeable file")
        if (self.flags & os.O_EXCL) and not self.writeable:
            raise IOError(errno.EINVAL, "O_EXCL without writeable file")
        if (self.flags & os.O_APPEND) and not self.writeable:
            raise IOError(errno.EINVAL, "O_EXCL without writeable file")

        if (self.flags & os.O_TRUNC):
            self.inode.truncate(0)

    def close(self):
        with self.lock:
            if self.inode is None:
                raise IOError(errno.EBADF, "Operation on a closed file")
            c = self.inode
            self.inode = None
            c.decref()

    def read(self, io, offset, length):
        with self.lock:
            if self.inode is None:
                raise IOError(errno.EBADF, "Operation on a closed file")
            if not self.readable:
                raise IOError(errno.EBADF, "File not readable")
            return self.inode.read(io, offset, length)

    def get_size(self):
        with self.lock:
            return self.inode.get_size()

    def write(self, io, offset, data):
        with self.lock:
            if self.inode is None:
                raise IOError(errno.EBADF, "Operation on a closed file")
            if not self.writeable:
                raise IOError(errno.EBADF, "File not writeable")
            if self.append:
                offset = None
            return self.inode.write(io, offset, data)

    def truncate(self, size):
        with self.lock:
            if self.inode is None:
                raise IOError(errno.EBADF, "Operation on a closed file")
            if not self.writeable:
                raise IOError(errno.EBADF, "File not writeable")
            return self.inode.truncate(size)


class CachedDirHandle(object):
    """
    Logical directory handle.
    """

    def __init__(self, upath, inode):
        self.inode = inode
        self.inode.incref()
        self.lock = threading.RLock()
        self.upath = upath

    def close(self):
        with self.lock:
            if self.inode is None:
                raise IOError(errno.EBADF, "Operation on a closed dir")
            c = self.inode
            self.inode = None
            c.decref()

    def listdir(self):
        with self.lock:
            if self.inode is None:
                raise IOError(errno.EBADF, "Operation on a closed dir")
            return self.inode.listdir()

    def get_attr(self):
        with self.lock:
            if self.inode is None:
                raise IOError(errno.EBADF, "Operation on a closed dir")
            return self.inode.get_attr()

    def get_child_attr(self, childname):
        with self.lock:
            if self.inode is None:
                raise IOError(errno.EBADF, "Operation on a closed dir")
            return self.inode.get_child_attr(childname)


class CachedFileInode(object):
    """
    Logical file on-disk. There should be only a single CachedFileInode
    instance is per each logical file.
    """

    def __init__(self, cachedb, upath, io, filecap, persistent=False):
        self.upath = upath
        self.closed = False
        self.refcnt = 0
        self.persistent = persistent
        self.invalidated = False

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
            if filecap is None:
                # Create new file
                raise ValueError()

            # Reuse cached metadata
            self.f = CryptFile(filename, key=key, mode='r+b')
            self.info = json_zlib_load(self.f)

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
                        self.info = ['file', {u'size': 0}]
                        self.dirty = True
                except IOError, err:
                    os.unlink(filename)
                    self.f.close()
                    raise

            # Create a data file
            self.f_data = CryptFile(filename_data, key=key_data, mode='w+b')

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
            raise IOError(errno.EREMOTEIO, "failed to retrieve information")
        self.f.truncate(0)
        self.f.seek(0)
        json_zlib_dump(self.info, self.f)

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

                if not self.persistent and self.upath is not None and not self.invalidated:
                    os.unlink(self.f_state.path)
                    os.unlink(self.f_data.path)
            self.closed = True

    def _do_rw(self, io, offset, length_or_data, write=False, no_result=False):
        if write:
            data = length_or_data
            length = len(data)
        else:
            length = length_or_data

        self.lock.acquire()
        try:
            preempted = False
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

                    if self.stream_f is not None and (self.stream_offset > c_offset or
                                                      c_offset >= self.stream_offset + 3*131072):
                        if not preempted:
                            # Try to yield to a different in-flight cache operation, in case there
                            # is one waiting for the lock
                            preempted = True
                            self.lock.release()
                            time.sleep(0)
                            self.lock.acquire()
                            continue

                        self.stream_f.close()
                        self.stream_f = None
                        self.stream_data = []

                    if self.stream_f is None:
                        self.stream_f = io.get_content(self.info[1][u'ro_uri'], c_offset, iscap=True)
                        self.stream_offset = c_offset
                        self.stream_data = []

                    read_offset = self.stream_offset
                    read_bytes = sum(len(x) for x in self.stream_data)
                    while read_offset + read_bytes < c_offset + c_length:
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
            raise IOError(errno.EREMOTEIO, "I/O error: %s" % (str(err),))
        finally:
            self.lock.release()

    def get_size(self):
        with self.lock:
            return self.block_cache.get_size()

    def get_attr(self):
        return dict(type='file', size=self.get_size())

    def read(self, io, offset, length):
        return self._do_rw(io, offset, length, write=False)

    def write(self, io, offset, data):
        """
        Write data to file. If *offset* is None, it means append.
        """
        with self.lock:
            if len(data) > 0:
                self.dirty = True
                if offset is None:
                    offset = self.get_size()
                self._do_rw(io, offset, data, write=True)

    def truncate(self, size):
        with self.lock:
            if size != self.block_cache.get_size():
                self.dirty = True
            self.block_cache.truncate(size)

    def _buffer_whole_file(self, io):
        self._do_rw(io, 0, self.block_cache.get_size(), write=False, no_result=True)

    def upload(self, io, parent_cap=None):
        with self.lock:
            if not self.dirty:
                # No changes
                return
            if self.upath is None:
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

            if parent_cap is None:
                upath = self.upath
                iscap = False
            else:
                upath = parent_cap + u"/" + ubasename(self.upath)
                iscap = True

            fw = Fwrapper(self.block_cache)
            try:
                filecap = io.put_file(upath, fw, iscap=iscap)
            except HTTPError, err:
                raise IOError(errno.EFAULT, "I/O error: %s" % (str(err),))

            filecap = filecap.decode('latin1').strip()
            self._load_info(filecap, io, iscap=True)

            self.dirty = False

    def unlink(self):
        with self.lock:
            if self.upath is not None and not self.invalidated:
                os.unlink(self.f.path)
                os.unlink(self.f_state.path)
                os.unlink(self.f_data.path)
            self.upath = None


class CachedDirInode(object):
    """
    Logical file on-disk directory. There should be only a single CachedDirInode
    instance is per each logical directory.
    """

    def __init__(self, cachedb, upath, io, dircap=None):
        self.upath = upath
        self.closed = False
        self.refcnt = 0
        self.lock = threading.RLock()
        self.invalidated = False

        filename, key = cachedb.get_filename_and_key(upath)
        try:
            with CryptFile(filename, key=key, mode='rb') as f:
                self.info = json_zlib_load(f)
            self.filename = filename
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
            json_zlib_dump(self.info, f)
        except (HTTPError, ValueError):
            os.unlink(filename)
            raise IOError(errno.EREMOTEIO, "failed to retrieve information")
        finally:
            f.close()

        self.filename = filename

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
            self.closed = True

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
                        rw_uri=info[1].get(u'rw_uri'),
                        ctime=info[1][u'metadata'][u'tahoe'][u'linkcrtime'],
                        mtime=info[1][u'metadata'][u'tahoe'][u'linkcrtime'])
        elif info[0] == u'filenode':
            return dict(type='file',
                        size=info[1][u'size'],
                        ro_uri=info[1][u'ro_uri'],
                        rw_uri=info[1].get(u'rw_uri'),
                        ctime=info[1][u'metadata'][u'tahoe'][u'linkcrtime'],
                        mtime=info[1][u'metadata'][u'tahoe'][u'linkcrtime'])
        else:
            raise IOError(errno.ENOENT, "invalid entry")

    def unlink(self):
        if self.upath is not None and not self.invalidated:
            os.unlink(self.filename)
        self.upath = None


class RandomString(object):
    def __init__(self, size):
        self.size = size

    def __len__(self):
        return self.size

    def __getitem__(self, k):
        if isinstance(k, slice):
            return os.urandom(len(xrange(*k.indices(self.size))))
        else:
            raise IndexError("invalid index")


def json_zlib_dump(obj, fp):
    try:
        fp.write(zlib.compress(json.dumps(obj), 3))
    except zlib.error:
        raise ValueError("compression error")


def json_zlib_load(fp):
    try:
        return json.load(ZlibDecompressor(fp))
    except zlib.error:
        raise ValueError("invalid compressed stream")


class ZlibDecompressor(object):
    def __init__(self, fp):
        self.fp = fp
        self.decompressor = zlib.decompressobj()
        self.buf = b""
        self.eof = False

    def read(self, sz=None):
        if sz is not None and not (sz > 0):
            return b""

        while not self.eof and (sz is None or sz > len(self.buf)):
            block = self.fp.read(131072)
            if not block:
                self.buf += self.decompressor.flush()
                self.eof = True
                break
            self.buf += self.decompressor.decompress(block)

        if sz is None:
            block = self.buf
            self.buf = b""
        else:
            block = self.buf[:sz]
            self.buf = self.buf[sz:]
        return block


def udirname(upath):
    return u"/".join(upath.split(u"/")[:-1])


def ubasename(upath):
    return upath.split(u"/")[-1]


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

    # Maximum size up to this time
    dl_size = _DOWNLOAD_SPEED * max(0, t - _LATENCY)

    # Time cost for re-retrieval
    return rate * (_LATENCY + min(dl_size, size) / _DOWNLOAD_SPEED)

