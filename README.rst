=============
tahoestaticfs
=============

Tahoestaticfs is a Fuse filesystem that enables read and write access
to files stored on a Tahoe-LAFS_ grid.

Tahoestaticfs is designed for static, unchanging data, and caches file
and directory metadata aggressively. Optionally, also file data can be
cached.

Compared to mounting Tahoe-LAFS directories via sshfs (as of
Tahoe-LAFS 1.9.2), Tahoestaticfs achieves better latency. This is true
also for accessing data not in cache (e.g. ``ls -laR /mnt/tahoe`` with
cold cache), due to the more aggressive directory metadata caching.
Moreover, tahoestaticfs also supports random access reads to stored
files, without requiring to download the full files.

.. _Tahoe-LAFS: http://tahoe-lafs.org/


Usage
-----

::

    tahoestaticfs [options] [mountpoint]

    Tahoe-LAFS directory mounted as a filesystem, with local
    caching. Cached data is encrypted with a key derived from the
    directory capability mounted.
    
    Dircap of the root directory is read from stdin on startup. In scripts, do::
    
        awk '/^root:/ {print $2}' < ~/.tahoe/private/aliases \
            | tahoestaticfs ...
    
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
        -w WRITE_LIFETIME, --write-cache-lifetime=WRITE_LIFETIME
                               Cache lifetime for write operations (seconds).
                               Default: 10 sec
        -r READ_LIFETIME, --read-cache-lifetime=READ_LIFETIME
                               Cache lifetime for read operations (seconds).
                               Default: 10 sec

For example::

    awk '/^root:/ {print $2}' < ~/.tahoe/private/aliases \
        tahoestaticfs -c /var/cache/tahoefscache -D -S 5G -u http://127.0.0.1:8090 /mnt/tahoestatic

.. warning::

   Do **not** do this::

       echo URI:DIR2:... | tahoestaticfs

   That makes the root capability visible to everyone. Instead, store the root
   capability in a file with appropriate permissions, for example reading it
   from your Tahoe-LAFS aliases file as shown above.


Caching and concurrency
-----------------------

Cached data and metadata becomes invalidated if it is older than the
corresponding cache lifetimes.  The cache lifetimes can be specified
separately for metadata/data read and write operations.

The cache will stay in a consistent state with the Tahoe grid if
modifications to the data are only performed via a single mounted
filesystem, even if the cache lifetimes are infinite.

If modifications are done directly to files on the grid e.g. from
other machines accessing the Tahoe storage, Tahoestaticfs filesystem
will reflect the state of the files in Tahoe storage only after
waiting one cache lifetime after the last modification.

Note that this is not an absolute guarantee, as Tahoe-LAFS itself does
`not guarantee full concurrency
<https://tahoe-lafs.org/trac/tahoe-lafs/browser/docs/frontends/webapi.rst#concurrency-issues>`__.

Nonzero cache lifetimes are in general necessary to obtain filesystem
metadata performance necessary for typical workloads.

The cache can be invalidated manually, via ``touch
<mountpoint>/.tahoestaticfs-invalidate``. To invalidate only the cache
of a subtree, do ``touch
<mountpoint>/<somedir>/.tahoestaticfs-invalidate``.


Encryption
----------

Tahoestaticfs encrypts cached data and metadata retrieved from network
before storing it on disk.

The purpose of the encryption is to hinder an attacker who, (i) has
read-only access to the cache files, and (ii) attempts to determine
either the root dircap or file data or metadata.

Each file is divided to 131072-byte chunks, and encryption is done
using AES-CBC-256 separately for each chunk, to enable random
access. The 16-byte IV for each chunk is random, and changed every
time the chunk is written on disk.

A 256-bit master encryption key is derived from the rootcap mounted,
combined with a randomly chosen 32-byte salt via PBKDF2. The iteration
count is determined so that it takes around one second on the system
in question, but is at least 10000. The salt is stored on-disk as-is.

The AES encryption keys are file-specific, and obtained via::

    prk = HKDF-SHA256-Extract(salt2, master-key)
    data_key | fn_key = HKDF-SHA256-Expand(prk, pathname, 96)

The salt2 is a second 32-byte randomly generated salt stored as-is
on-disk.  The 32-byte data_key is used as the AES-CBC encryption key.
The 64-byte fn_key is used to generate filenames via
HMAC-SHA512(fn_key, pathname).
