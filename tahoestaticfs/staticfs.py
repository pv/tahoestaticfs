import os
import re
import sys
import errno
import stat
import traceback
import threading
import logging
import logging.handlers

import fuse

from tahoestaticfs.cachedb import CacheDB
from tahoestaticfs.tahoeio import TahoeConnection

print_lock = threading.Lock()


def ioerrwrap(func):
    def wrapper(*a, **kw):
        try:
            return func(*a, **kw)
        except (IOError, OSError) as e:
            with print_lock:
                if isinstance(e, IOError) and getattr(e, 'errno', None) == errno.ENOENT:
                    logging.debug("Failed operation", exc_info=True)
                else:
                    logging.info("Failed operation", exc_info=True)
            if hasattr(e, 'errno') and isinstance(e.errno, int):
                # Standard operation
                return -e.errno
            return -errno.EACCES
        except:
            with print_lock:
                logging.warning("Unexpected exception", exc_info=True)
            return -errno.EIO

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
        self.parser.add_option('-w', '--write-cache-lifetime', dest='write_lifetime', default='10',
                               help="Cache lifetime for write operations (seconds). Default: 10 sec")
        self.parser.add_option('-r', '--read-cache-lifetime', dest='read_lifetime', default='10',
                               help="Cache lifetime for read operations (seconds). Default: 10 sec")
        self.parser.add_option('-l', '--log-level', dest='log_level', default='warning',
                               help="Log level (error, warning, info, debug). Default: warning")
        self.parser.add_option('-t', '--timeout', dest='timeout', default='30',
                               help="Network timeout. Default: 30s")

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

        try:
            log_level = parse_log_level(options.log_level)
        except ValueError:
            print(("error: --log-level %r is not a valid log level" % (options.log_level,)))
            sys.exit(1)

        node_url = options.node_url

        try:
            cache_size = parse_size(options.cache_size)
        except ValueError:
            print(("error: --cache-size %r is not a valid size specifier" % (options.cache_size,)))
            sys.exit(1)

        try:
            read_lifetime = parse_lifetime(options.read_lifetime)
        except ValueError:
            print(("error: --read-cache-lifetime %r is not a valid lifetime" % (options.read_lifetime,)))
            sys.exit(1)

        try:
            write_lifetime = parse_lifetime(options.write_lifetime)
        except ValueError:
            print(("error: --write-cache-lifetime %r is not a valid lifetime" % (options.write_lifetime,)))
            sys.exit(1)

        try:
            timeout = float(options.timeout)
            if not 0 < timeout < float('inf'):
                raise ValueError()
        except ValueError:
            print(("error: --timeout %r is not a valid timeout" % (options.timeout,)))
            sys.exit(1)

        logger = logging.getLogger('')
        if self.fuse_args.modifiers.get('foreground'):
            # console logging only
            handler = logging.StreamHandler()
            fmt = logging.Formatter(fmt=("%(asctime)s tahoestaticfs[%(process)d]: " +
                                         self.fuse_args.mountpoint + " %(levelname)s: %(message)s"))
        else:
            # to syslog
            handler = logging.handlers.SysLogHandler(address='/dev/log')
            fmt = logging.Formatter(fmt=("tahoestaticfs[%(process)d]: " +
                                         self.fuse_args.mountpoint + ": %(levelname)s: %(message)s"))

        handler.setFormatter(fmt)
        logger.addHandler(handler)
        logger.setLevel(log_level)

        rootcap = input('Root dircap: ').strip()

        if not os.path.isdir(options.cache):
            os.makedirs(options.cache)

        self.cache = CacheDB(options.cache, rootcap, node_url,
                             cache_size=cache_size, 
                             cache_data=options.cache_data,
                             read_lifetime=read_lifetime,
                             write_lifetime=write_lifetime)
        self.io = TahoeConnection(node_url, rootcap, timeout)

        fuse.Fuse.main(self, args)

    # -- Directory handle ops

    @ioerrwrap
    def readdir(self, path, offset):
        upath = self.cache.get_upath(path)

        entries = [fuse.Direntry(b'.'), 
                   fuse.Direntry(b'..')]

        f = self.cache.open_dir(upath, self.io)
        try:
            for c in f.listdir():
                entries.append(fuse.Direntry(self.cache.path_from_upath(c)))
        finally:
            self.cache.close_dir(f)

        return entries

    # -- File ops

    @ioerrwrap
    def open(self, path, flags):
        upath = self.cache.get_upath(path)
        basename = os.path.basename(upath)
        if basename == '.tahoestaticfs-invalidate' and (flags & os.O_CREAT):
            self.cache.invalidate(os.path.dirname(upath))
            return -errno.EACCES
        return self.cache.open_file(upath, self.io, flags)

    @ioerrwrap
    def release(self, path, flags, f):
        upath = self.cache.get_upath(path)
        try:
            # XXX: if it fails, silent data loss (apart from logs)
            self.cache.upload_file(f, self.io)
            return 0
        finally:
            self.cache.close_file(f)

    @ioerrwrap
    def read(self, path, size, offset, f):
        upath = self.cache.get_upath(path)
        return f.read(self.io, offset, size)

    @ioerrwrap
    def create(self, path, flags, mode):
        # no support for mode in Tahoe, so discard it
        return self.open(path, flags)
 
    @ioerrwrap
    def write(self, path, data, offset, f):
        upath = self.cache.get_upath(path)
        self.io.wait_until_write_allowed()
        f.write(self.io, offset, data)
        return len(data)

    @ioerrwrap
    def ftruncate(self, path, size, f):
        f.truncate(size)
        return 0

    @ioerrwrap
    def truncate(self, path, size):
        upath = self.cache.get_upath(path)

        f = self.cache.open_file(upath, self.io, os.O_RDWR)
        try:
            f.truncate(size)
            self.cache.upload_file(f, self.io)
        finally:
            self.cache.close_file(f)
        return 0

    # -- Handleless ops

    @ioerrwrap
    def getattr(self, path):
        upath = self.cache.get_upath(path)

        info = self.cache.get_attr(upath, self.io)

        if info['type'] == 'dir':
            st = fuse.Stat()
            st.st_mode = stat.S_IFDIR | stat.S_IRUSR | stat.S_IXUSR
            st.st_nlink = 1
        elif info['type'] == 'file':
            st = fuse.Stat()
            st.st_mode = stat.S_IFREG | stat.S_IRUSR | stat.S_IWUSR
            st.st_nlink = 1
            st.st_size = info['size']
            st.st_mtime = info['mtime']
            st.st_ctime = info['ctime']
        else:
            return -errno.EBADF

        return st

    @ioerrwrap
    def unlink(self, path):
        upath = self.cache.get_upath(path)
        self.cache.unlink(upath, self.io, is_dir=False)
        return 0

    @ioerrwrap
    def rmdir(self, path):
        upath = self.cache.get_upath(path)
        self.cache.unlink(upath, self.io, is_dir=True)
        return 0

    @ioerrwrap
    def mkdir(self, path, mode):
        # *mode* is dropped; not supported on tahoe
        upath = self.cache.get_upath(path)
        self.cache.mkdir(upath, self.io)
        return 0


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
    size_re = re.compile(r'^\s*(\d+)\s*(%s)?\s*$' % ("|".join(list(multipliers.keys())),), 
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


def parse_lifetime(lifetime_str):
    if lifetime_str.lower() in ('inf', 'infinity', 'infinite'):
        return 100*365*24*60*60

    try:
        return int(lifetime_str)
    except ValueError:
        raise ValueError("invalid lifetime specifier")


def parse_log_level(log_level):
    try:
        return {'error': logging.ERROR,
                'warning': logging.WARNING,
                'info': logging.INFO,
                'debug': logging.DEBUG}[log_level]
    except KeyError:
        raise ValueError("invalid log level specifier")
