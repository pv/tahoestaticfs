import os
import re
import sys
import errno
import stat
import traceback
import threading
import logging

import fuse

from tahoestaticfs.cachedb import CacheDB
from tahoestaticfs.tahoeio import TahoeConnection


print_lock = threading.Lock()


def ioerrwrap(func):
    def wrapper(*a, **kw):
        try:
            return func(*a, **kw)
        except (IOError, OSError), e:
            # Unexpected error condition: print traceback
            with print_lock:
                msg = "\n".join(["-"*80,
                                 traceback.format_exc(),
                                 "-"*80])
                logging.debug(msg)
            if hasattr(e, 'errno') and isinstance(e.errno, int):
                # Standard operation
                return -e.errno
            return -errno.EACCES
        except:
            # Unexpected error condition: print traceback
            with print_lock:
                msg = "\n".join(["-"*80,
                                 traceback.format_exc(),
                                 "-"*80])
                logging.warning(msg)
            raise

    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    return wrapper


class TahoeStaticFS(fuse.Fuse):
    def __init__(self, *args, **kwargs):
        super(TahoeStaticFS, self).__init__(*args, **kwargs)
        self.parser.add_option('-c', '--cache', dest='cache', help="Cache directory")
        self.parser.add_option('-u', '--node-url', dest='node_url', help="Tahoe gateway node URL")
        self.parser.add_option('-D', '--cache-data', dest='cache_data', action="store_true", help="Cache also file data")
        self.parser.add_option('-S', '--cache-size', dest='cache_size', help="Target cache size", default="1GB")

    def main(self, args=None):
        if not self.fuse_args.mount_expected():
            fuse.Fuse.main(self, args)
            return

        options = self.cmdline[0]
        if options.cache is None:
            print("error: --cache not specified")
            sys.exit(1)
        if options.node_url is None:
            print("error: --node-url not specified")
            sys.exit(1)

        if not os.path.isdir(options.cache):
            os.makedirs(options.cache)

        cap_env = 'TAHOESTATICFS_DIRCAP'
        if cap_env in os.environ:
            rootcap = os.environ[cap_env]
            del os.environ[cap_env]
        else:
            rootcap = raw_input('Root dircap: ').strip()

        try:
            rootcap = rootcap.decode('ascii')
        except UnicodeError:
            print("error: invalid rootcap (non-ascii characters)")
            sys.exit(1)

        try:
            node_url = options.node_url.decode(sys.getfilesystemencoding())
        except UnicodeError:
            print("error: invalid node URL")
            sys.exit(1)

        try:
            cache_size = parse_size(options.cache_size)
        except ValueError:
            print("error: --cache-size %r is not a valid size specifier" % (options.cache_size,))

        self.cache = CacheDB(options.cache, rootcap, node_url,
                             cache_size=cache_size, 
                             cache_data=options.cache_data)
        self.io = TahoeConnection(node_url, rootcap)

        fuse.Fuse.main(self, args)

    # -- Directory handle ops

    @ioerrwrap
    def readdir(self, path, offset):
        upath = self.cache.get_upath(path)

        entries = [fuse.Direntry(b'.'), 
                   fuse.Direntry(b'..')]
        encoding = sys.getfilesystemencoding()

        f = self.cache.open_dir(upath, self.io)
        try:
            for c in f.listdir():
                entries.append(fuse.Direntry(c.encode(encoding)))
        finally:
            self.cache.close_dir(f)

        return entries

    # -- File ops

    @ioerrwrap
    def open(self, path, flags):
        upath = self.cache.get_upath(path)
        if upath == u'.tahoestaticfs-invalidate' and (flags & os.O_CREAT):
            self.cache.invalidate()
        return self.cache.open_file(upath, self.io, flags)

    @ioerrwrap
    def release(self, path, flags, f):
        self.cache.close_file(f)
        return 0

    @ioerrwrap
    def read(self, path, size, offset, f):
        upath = self.cache.get_upath(path)
        return f.read(self.io, offset, size)

    @ioerrwrap
    def create(self, path, flags, mode):
        upath = self.cache.get_upath(path)
        if upath == u'.tahoestaticfs-invalidate' and (flags & os.O_CREAT):
            self.cache.invalidate()
        return -errno.EACCES

    # -- Handleless ops

    @ioerrwrap
    def getattr(self, path):
        upath = self.cache.get_upath(path)

        if upath == u'':
            dir = self.cache.open_dir(upath, self.io)
            try:
                info = dir.get_attr()
            finally:
                self.cache.close_dir(dir)
        else:
            upath_parent = self.cache.get_upath_parent(path)
            dir = self.cache.open_dir(upath_parent, self.io)
            try:
                info = dir.get_child_attr(os.path.basename(upath))
            finally:
                self.cache.close_dir(dir)

        if info['type'] == 'dir':
            st = fuse.Stat()
            st.st_mode = stat.S_IFDIR | stat.S_IRUSR | stat.S_IXUSR
            st.st_nlink = 1
        elif info['type'] == u'file':
            st = fuse.Stat()
            st.st_mode = stat.S_IFREG | stat.S_IRUSR | stat.S_IWUSR
            st.st_nlink = 1
            st.st_size = info['size']
            st.st_mtime = info['mtime']
            st.st_ctime = info['ctime']
        else:
            return -errno.EBADF

        return st


def parse_size(size_str):
    multipliers = {
        't': 1000**4,
        'g': 1000**3,
        'm': 1000**2,
        'k': 1000**1,
        'tb': 1000**4,
        'gb': 1000**3,
        'mb': 1000**2,
        'kb': 1000**1,
        'tib': 1024**4,
        'gib': 1024**3,
        'mib': 1024**2,
        'kib': 1024**1,
    }
    size_re = re.compile(r'^\s*(\d+)\s*(%s)?\s*$' % ("|".join(multipliers.keys()),), 
                         re.I)

    m = size_re.match(size_str)
    if not m:
        raise ValueError("not a valid size specifier")

    size = int(m.group(1))
    multiplier = m.group(2)
    if multiplier is not None:
        try:
            size *= multipliers[multiplier.lower()]
        except KeyError:
            raise ValueError("invalid size multiplier")

    return size
