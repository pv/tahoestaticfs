import os
import sys
import errno
import stat
import traceback

import fuse

from tahoefuse.cachedb import CacheDB
from tahoefuse.tahoeio import TahoeIO, HTTPError


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

        self.cache = CacheDB(options.cache, "a"*32)

        node_url = options.node_url.decode(sys.getfilesystemencoding())
        rootcap = self.rootcap.decode('ascii')
        self.io = TahoeIO(node_url, rootcap)
        del self.rootcap

        fuse.Fuse.main(self, args)

    def getattr(self, path):
        try:
            upath = path.decode(sys.getfilesystemencoding())
        except UnicodeError, e:
            # all tahoe files have valid unicode names
            return -errno.ENOENT

        try:
            info = self.io.connection.get_info(upath)
        except HTTPError, err:
            if err.code in (404,):
                return -errno.ENOENT
            raise IOError(err)

        if info[0] == u'dirnode':
            st = fuse.Stat()
            st.st_mode = stat.S_IFDIR | stat.S_IRUSR | stat.S_IXUSR
            st.st_nlink = 1
        elif info[0] == u'filenode':
            st = fuse.Stat()
            st.st_mode = stat.S_IFREG | stat.S_IRUSR
            st.st_nlink = 1
            st.st_size = info[1][u'size']
            st.st_mtime = info[1][u'metadata'][u'tahoe'][u'linkmotime']
            st.st_ctime = info[1][u'metadata'][u'tahoe'][u'linkcrtime']
        else:
            return -errno.EBADF

        return st

    def readdir(self, path, offset):
        try:
            upath = path.decode(sys.getfilesystemencoding())
        except UnicodeError, e:
            # all tahoe files have valid unicode names
            return -errno.ENOENT

        try:
            entries = [fuse.Direntry(b'.'), 
                       fuse.Direntry(b'..')]

            encoding = sys.getfilesystemencoding()
            for c in self.io.listdir(upath):
                entries.append(fuse.Direntry(c.encode(encoding)))
            return entries
        except:
            traceback.print_exc()
            raise

    def read(self, path, size, offset):
        try:
            upath = path.decode(sys.getfilesystemencoding())
        except UnicodeError, e:
            # all tahoe files have valid unicode names
            return -errno.ENOENT

        return self.io.connection.get_content(upath, offset, size).read()

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
