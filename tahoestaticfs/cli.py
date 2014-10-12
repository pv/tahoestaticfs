"""tahoestaticfs [options] [mountpoint]

Tahoe-LAFS directory mounted as a read-only file system, with local
caching. Cached data is encrypted with a key derived from the
directory capability mounted.

Dircap of the root directory is read from stdin on startup. In scripts, do::

    awk '/^root:/ {print $2}' < ~/.tahoe/private/aliases \\
        | tahoestaticfs ...

Cache can be invalidated by `touch <mountpoint>/.tahoestaticfs-invalidate`,
or by removing files in the cache directory.

"""
import os
import sys
import fuse
import logging

from tahoestaticfs.staticfs import TahoeStaticFS
from tahoestaticfs.version import __version__

fuse.fuse_python_api = (0, 2)

def main():
    logging.basicConfig(level=logging.INFO)

    usage = __doc__.strip()
    usage += "".join(fuse.Fuse.fusage.splitlines(1)[2:])
    fs = TahoeStaticFS(version=__version__, usage=usage, dash_s_do='undef')
    fs.parse(errex=1)
    fs.main()

if __name__ == "__main__":
    main()
