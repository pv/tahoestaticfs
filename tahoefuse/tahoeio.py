from urllib2 import Request, urlopen, quote, HTTPError
import json
import threading
import shutil


class TahoeResponse(object):
    def __init__(self, connection, req):
        self.connection = connection
        self.response = urlopen(req)

    def read(self, size=None):
        return self.response.read(size)

    def close(self):
        self.response.close()
        self.connection._release_response(self)


class TahoeConnection(object):
    def __init__(self, base_url, rootcap, max_connections=10):
        assert isinstance(base_url, unicode)
        assert isinstance(rootcap, unicode)

        self.base_url = (base_url.rstrip('/') + '/uri').encode('utf-8')
        self.rootcap = rootcap.encode('utf-8')

        self.connections = []
        self.lock = threading.Lock()

        self.semaphore = threading.Semaphore(max_connections)

    def _get_response(self, req):
        self.semaphore.acquire()
        with self.lock:
            try:
                response = TahoeResponse(self, req)
            except:
                self.semaphore.release()
                raise
            self.connections.append(response)
            return response

    def _release_response(self, response):
        with self.lock:
            if response in self.connections:
                self.semaphore.release()
                self.connections.remove(response)

    def _url(self, path, params={}, iscap=False):
        assert isinstance(path, unicode), path

        if iscap:
            path = self.base_url + b'/' + path.encode('ascii')
        else:
            path = path.encode('utf-8')
            path = quote(path).lstrip(b'/')
            path = self.base_url + b'/' + self.rootcap + b'/' + path

        if params:
            path += b'?'

            for k, v in params.items():
                assert isinstance(k, unicode), k
                assert isinstance(v, unicode), v
                if not path.endswith(b'?'):
                    path += b'&'
                k = quote(k.encode('utf-8'), safe=b'')
                v = quote(v.encode('utf-8'), safe=b'')
                path += k
                path += b'='
                path += v

        return path

    def _get_request(self, method, path, offset=None, length=None, data=None, params={}, iscap=False):
        headers = {b'Accept': b'text/plain'}

        if offset is not None or length is not None:
            if offset is None:
                start = b"0"
                offset = 0
            else:
                start = str(offset).encode('utf-8')
            if length is None:
                end = b""
            else:
                end = str(offset + length - 1).encode('utf-8')
            headers['Range'] = b'bytes=' + start + b'-' + end

        req = Request(self._url(path, params, iscap=iscap),
                      data=data,
                      headers=headers)
        req.get_method = lambda: method
        return req

    def _get(self, path, params={}, offset=None, length=None, iscap=False):
        req = self._get_request("GET", path, params=params, offset=offset, length=length, iscap=iscap)
        return self._get_response(req)

    def _post(self, path, data=None, params={}, iscap=False):
        req = self._get_request("POST", path, data=data, params=params, iscap=iscap)
        return self._get_response(req)

    def _put(self, path, data=None, params={}, iscap=False):
        req = self._get_request("PUT", path, data=data, params=params, iscap=iscap)
        return self._get_response(req)

    def _delete(self, path, params={}, iscap=False):
        req = self._get_request("DELETE", path, params=params, iscap=iscap)
        return self._get_response(req)

    def get_info(self, path, iscap=False):
        f = self._get(path, {u't': u'json'}, iscap=iscap)
        try:
            data = json.load(f)
        finally:
            f.close()
        return data

    def get_content(self, path, offset=None, length=None, iscap=False):
        return self._get(path, offset=offset, length=length, iscap=iscap)

    def put_file(self, path, f):
        f = self._put(path, data=f)
        try:
            return f.read()
        finally:
            f.close()
