import os
import shutil
import tempfile
from StringIO import StringIO

from nose.tools import assert_equal

from tahoestaticfs.cachedb import json_zlib_load, json_zlib_dump
from tahoestaticfs.crypto import CryptFile


class TestJsonZlib(object):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.file_name = os.path.join(self.tmpdir, 'test.dat')

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_roundtrip(self):
        key = "a"*32
        with CryptFile(self.file_name, key, 'w+b') as fp:
            for sz in [1, 2, 10, 100, 1000, 10000]:
                data = {
                    u'a': [u'b']*sz,
                    u'b': [u'c']*sz
                }

                fp.truncate(0)
                fp.seek(0)
                json_zlib_dump(data, fp)

                fp.seek(0)
                data_2 = json_zlib_load(fp)

                assert_equal(data_2, data)
