"""tahoestaticfs [options] [mountpoint]

Tahoe-LAFS directory mounted as a file system, with local caching.

Cap of the root directory is to be passed in in the TAHOESTATICFS_CAP
environment variable. If it is not given, it is read from stdin on start.

"""
import os
import sys
import fuse

from tahoestaticfs.staticfs import TahoeStaticFS
from tahoestaticfs.version import __version__

fuse.fuse_python_api = (0, 2)

def main():
    usage = __doc__.strip()
    usage += "".join(fuse.Fuse.fusage.splitlines(1)[2:])

    cap_env = 'TAHOESTATICFS_DIRCAP'
    rootcap = None
    if '-h' not in sys.argv and '--help' not in sys.argv:
        if cap_env in os.environ:
            rootcap = os.environ[cap_env]
        else:
            rootcap = raw_input('Root dircap: ')

    fs = TahoeStaticFS(rootcap=rootcap, version=__version__, usage=usage)
    fs.parse(errex=1)
    fs.main()

if __name__ == "__main__":
    main()
