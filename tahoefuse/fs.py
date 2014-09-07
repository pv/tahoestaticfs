import os
import sys
import errno
import stat
import traceback

import fuse

from tahoefuse.cachedb import CacheDB
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

        io = TahoeConnection(node_url, rootcap)
        self.cache = CacheDB(options.cache, "a"*32, io)

        fuse.Fuse.main(self, args)

    def getattr(self, path):
        try:
            info = self.cache.getattr(path)
        except:
            traceback.print_exc()
            raise

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

    def readdir(self, path, offset):
        entries = [fuse.Direntry(b'.'), 
                   fuse.Direntry(b'..')]

        encoding = sys.getfilesystemencoding()
        for c in self.cache.listdir(path):
            entries.append(fuse.Direntry(c.encode(encoding)))
        return entries

    def read(self, path, size, offset):
        try:
            return self.cache.read(path, offset, size)
        except:
            traceback.print_exc()
            raise

    def open(self, path, flags):
        try:
            upath = path.decode(sys.getfilesystemencoding())
        except UnicodeError, e:
            # all tahoe files have valid unicode names
            return -errno.ENOENT

        if flags & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) != os.O_RDONLY:
            return -errno.EACCES
        else:
            return 0
