import os
import sys
import errno

import fuse

from tahoefuse.cachedb import CacheDB


class TahoeFuseFS(fuse.Fuse):
    def __init__(self, *args, **kwargs):
        super(self, TahoeFuseFS).__init__(self, *args, **kwargs)
        opts = self.parse(['-s'])
        self.parser.add_option('-c', '--cache', dest='cache', help="Cache directory")

    def main(self, args=None):
        options = self.cmdline[0]

        if options.cache is None:
            print("error: --cache not specified")
            sys.exit(1)

        if not os.path.isdir(options.cache):
            os.makedirs(options.cache)

        self.cache = CacheDB(options.cache, "a"*32)

        fuse.Fuse.main(self, args)

    def getattr(self, path):
        pass

    def readdir(self, path, offset):
        pass

    def read(self, path, size, offset):
        pass

    def open(self, path, flags):
        pass

