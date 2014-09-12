import os
import sys
import errno
import stat
import traceback

import fuse

from tahoefuse.cachedb import CacheDB, CachedFile, CachedDir
from tahoefuse.tahoeio import TahoeConnection


class TahoeFuseFS(fuse.Fuse):
    def __init__(self, rootcap, *args, **kwargs):
        super(TahoeFuseFS, self).__init__(*args, **kwargs)
        opts = self.parse(['-s'])
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

    def opendir(self, path):
        upath = self.cache.get_upath(path)
        return CachedDir(self.cache, upath, self.io)

    def releasedir(self, path, f):
        f.close()

    def readdir(self, path, offset, f):
        upath = self.cache.get_upath(path)

        entries = [fuse.Direntry(b'.'), 
                   fuse.Direntry(b'..')]
        encoding = sys.getfilesystemencoding()

        for c in f.listdir():
            entries.append(fuse.Direntry(c.encode(encoding)))

        return entries

    # -- File ops


    def open(self, path, flags):
        upath = self.cache.get_upath(path)
        if flags & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) != os.O_RDONLY:
            return -errno.EACCES
        else:
            return CachedFile(self.cache, upath, self.io)

    def release(self, path, flags, f):
        f.close()
        return 0

    def read(self, path, size, offset, f):
        upath = self.cache.get_upath(path)
        return f.read(self.io, offset, size)

    # -- Handleless ops

    def getattr(self, path):
        upath = self.cache.get_upath(path)

        if upath == u'':
            with CachedDir(self.cache, upath, self.io) as dir:
                info = dir.get_attr()
        else:
            upath_parent = self.cache.get_upath_parent(path)
            with CachedDir(self.cache, upath_parent, self.io) as dir:
                info = dir.get_child_attr(os.path.basename(upath))

        if info['type'] == 'dir':
            st = fuse.Stat()
            st.st_mode = stat.S_IFDIR | stat.S_IRUSR | stat.S_IXUSR
            st.st_nlink = 1
        elif info['type'] == u'file':
            st = fuse.Stat()
            st.st_mode = stat.S_IFREG | stat.S_IRUSR
            st.st_nlink = 1
            st.st_size = info['size']
            st.st_mtime = info['mtime']
            st.st_ctime = info['ctime']
        else:
            return -errno.EBADF

        return st
