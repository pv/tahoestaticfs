"""
Cache metadata and data of a directory tree.
"""

import os
import struct
import fcntl

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256, SHA512
from Crypto.Util import Counter
from Crypto import Random


class CacheDB(object):
    def __init__(self, path, key):
        if not os.path.isdir(path):
            raise IOError("Cache directory is not an existing directory")
        self.path = path
        self.key = key


    def _get_file_from_filecap(self, cap):
        return HMAC.new(self.key, msg=b"FILE:"+cap, digestmod=SHA512).hexdigest()

    def _get_file_from_fileinfocap(self, cap):
        return HMAC.new(self.key, msg=b"FILEINFO:"+cap, digestmod=SHA512).hexdigest()

    def _get_file_from_dircap(self, cap):
        return HMAC.new(self.key, msg=b"DIR:"+cap, digestmod=SHA512).hexdigest()
