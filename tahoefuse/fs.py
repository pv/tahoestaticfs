import os
import sys
import errno
import stat
import traceback
import threading

import fuse

from tahoefuse.cachedb import CacheDB
from tahoefuse.tahoeio import TahoeConnection


print_lock = threading.Lock()


def ioerrwrap(func):
    def wrapper(*a, **kw):
        try:
            return func(*a, **kw)
        except (IOError, OSError), e:
            # Unexpected error condition: print traceback
            with print_lock:
                print >> sys.stderr, "-"*80
                traceback.print_exc()
                print >> sys.stderr, "-"*80
                sys.stderr.flush()
                sys.stdout.flush()
            if hasattr(e, 'errno') and isinstance(e.errno, int):
                # Standard operation
                return -e.errno
            return -errno.EACCES
        except:
            # Unexpected error condition: print traceback
            with print_lock:
                print >> sys.stderr, "-"*80
                traceback.print_exc()
                print >> sys.stderr, "-"*80
                sys.stderr.flush()
                sys.stdout.flush()
            raise

    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    return wrapper


class TahoeFuseFS(fuse.Fuse):
    def __init__(self, rootcap, *args, **kwargs):
        super(TahoeFuseFS, self).__init__(*args, **kwargs)
        self.parser.add_option('-c', '--cache', dest='cache', help="Cache directory")
        self.parser.add_option('-u', '--node-url', dest='node_url', help="Tahoe gateway node URL")
        self.rootcap = rootcap

    def main(self, args=None):
        options = self.cmdline[0]

        if options.cache is None:
            print("error: --cache not specified")
            sys.exit(1)
        if options.node_url is None:
            print("error: --node-url not specified")
            sys.exit(1)

        if not os.path.isdir(options.cache):
            os.makedirs(options.cache)

        node_url = options.node_url.decode(sys.getfilesystemencoding())
        rootcap = self.rootcap.decode('ascii')
        del self.rootcap

        self.cache = CacheDB(options.cache, rootcap, node_url)
        self.io = TahoeConnection(node_url, rootcap)

        fuse.Fuse.main(self, args)

    # -- Directory handle ops

    @ioerrwrap
    def readdir(self, path, offset):
        upath = self.cache.get_upath(path)

        entries = [fuse.Direntry(b'.'), 
                   fuse.Direntry(b'..')]
        encoding = sys.getfilesystemencoding()

        with self.cache.open_dir(upath, self.io) as f:
            for c in f.listdir():
                entries.append(fuse.Direntry(c.encode(encoding)))

        return entries

    # -- File ops

    @ioerrwrap
    def open(self, path, flags):
        with print_lock:
            print "OPEN", path, flags
        upath = self.cache.get_upath(path)
        return self.cache.open_file(upath, self.io, flags)

    @ioerrwrap
    def release(self, path, flags, f):
        with print_lock:
            print "RELEASE", path, flags, f
        upath = self.cache.get_upath(path)
        try:
            f.upload(self.io, upath)
        finally:
            f.close()
        return 0

    @ioerrwrap
    def read(self, path, size, offset, f):
        with print_lock:
            print "READ", path, size, offset, f
        upath = self.cache.get_upath(path)
        return f.read(self.io, offset, size)

    @ioerrwrap
    def write(self, path, data, offset, f):
        with print_lock:
            print "WRITE", path, len(data), offset, f
        upath = self.cache.get_upath(path)
        f.write(self.io, offset, data)
        return len(data)

    @ioerrwrap
    def ftruncate(self, path, size, f):
        with print_lock:
            print "FTRUNCATE", path, size, f
        f.truncate(size)
        return 0

    @ioerrwrap
    def truncate(self, path, size):
        with print_lock:
            print "TRUNCATE", path, size
        upath = self.cache.get_upath(path)
        with self.cache.open_file(upath, self.io, os.O_RDWR) as f:
            f.truncate(size)
            f.upload(self.io, upath)
        return 0

    # -- Handleless ops

    @ioerrwrap
    def getattr(self, path):
        upath = self.cache.get_upath(path)

        if upath == u'':
            with self.cache.open_dir(upath, self.io) as dir:
                info = dir.get_attr()
        else:
            upath_parent = self.cache.get_upath_parent(path)
            with self.cache.open_dir(upath_parent, self.io) as dir:
                info = dir.get_child_attr(os.path.basename(upath))

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
