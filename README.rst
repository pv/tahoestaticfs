=============
tahoestaticfs
=============

Tahoestaticfs is a Fuse filesystem that enables read-only access to
an unchanging tree of files stored on a Tahoe-LAFS_ grid.

It is designed for static, unchanging data, and caches file and
directory metadata aggressively. Optionally, also file data can be
cached.

The cache is never invalidated automatically, and the files and
directories stored are assumed to never change. The cache can be
invalidated manually, via ``touch <mountpoint>/.tahoestaticfs-invalidate``.

.. _Tahoe-LAFS: http://tahoe-lafs.org/

Usage
-----

::

    tahoestaticfs [options] [mountpoint]

    Tahoe-LAFS directory mounted as a read-only file system, with local
    caching. Cached data is encrypted with a key derived from the
    directory capability mounted.
    
    Dircap of the root directory is to be passed in in TAHOESTATICFS_DIRCAP
    environment variable. If it is not given, it is read from stdin on start.
    
    Cache can be invalidated by `touch <mountpoint>/.tahoestaticfs-invalidate`,
    or by removing files in the cache directory.

    Options:
        --version              show program's version number and exit
        -h, --help             show this help message and exit
        -o opt,[opt...]        mount options
        -c CACHE, --cache=CACHE
                               Cache directory
        -u NODE_URL, --node-url=NODE_URL
                               Tahoe gateway node URL
        -D, --cache-data       Cache also file data
        -S CACHE_SIZE, --cache-size=CACHE_SIZE
                               Target cache size

For example::

    TAHOESTATICFS_DIRCAP="`awk '/^root:/ {print $2}' < ~./tahoe/private/aliases`" \
    tahoestaticfs -c /var/cache/tahoefscache -D -S 5G -u http://127.0.0.1:8090 /mnt/tahoestatic


Encrypted cache
---------------

Tahoestaticfs caches data and metadata retrieved from network on disk.

The purpose of the encryption is to hinder an attacker who, (i) has
read-only access to the cache files, and (ii) attempts to determine
either the root dircap or file data or metadata.

Each file is divided to 131072-byte chunks, and encryption is done
using AES-CBC-256 separately for each chunk, to enable random
access. The 16-byte IV for each chunk is random, and changed every
time the chunk is written on disk.

File sizes are exposed in plaintext; other metadata is encrypted.  All
other data is also encrypted, including temporary files.

A 256-bit master encryption key is derived from the rootcap mounted,
combined with a randomly chosen 32-byte salt via PBKDF2. The iteration
count is determined so that it takes around one second on the system
in question, but is at least 10000. The salt is stored on-disk as-is.

The AES encryption keys are file-specific, and obtained via::

    prk = HKDF-SHA256-Extract(salt2, master-key)
    data_key | fn_key = HKDF-SHA256-Expand(prk, pathname, 64)

The salt2 is a second 32-byte randomly generated salt stored as-is
on-disk.  The 32-byte data_key is used as the AES-CBC encryption key.
The 32-byte fn_key is used to generate filenames via
HMAC-SHA256(fn_key, pathname).
