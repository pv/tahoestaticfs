from urllib2 import Request, urlopen, quote, HTTPError
import json
import threading
import shutil


class TahoeResponse(object):
    def __init__(self, connection, req, is_put):
        self.connection = connection
        self.response = urlopen(req)
        self.is_put = is_put

    def read(self, size=None):
        return self.response.read(size)

    def close(self):
        self.response.close()
        self.connection._release_response(self, self.is_put)


class TahoeConnection(object):
    def __init__(self, base_url, rootcap, max_connections=10):
        assert isinstance(base_url, unicode)
        assert isinstance(rootcap, unicode)

        self.base_url = (base_url.rstrip('/') + '/uri').encode('utf-8')
        self.rootcap = rootcap.encode('utf-8')

        self.connections = []
        self.lock = threading.Lock()

        put_conns = max(1, max_connections//2)
        get_conns = max(1, max_connections - put_conns)

        self.get_semaphore = threading.Semaphore(get_conns)
        self.put_semaphore = threading.Semaphore(put_conns)

    def _get_response(self, req, is_put):
        semaphore = self.put_semaphore if is_put else self.get_semaphore

        semaphore.acquire()
        try:
            response = TahoeResponse(self, req, is_put)
            with self.lock:
                self.connections.append(response)
                return response
        except:
            semaphore.release()
            raise

    def _release_response(self, response, is_put):
        semaphore = self.put_semaphore if is_put else self.get_semaphore

        with self.lock:
            if response in self.connections:
                semaphore.release()
                self.connections.remove(response)

    def _url(self, path, params={}, iscap=False):
        assert isinstance(path, unicode), path

        path = path.encode('utf-8')
        path = quote(path).lstrip(b'/')
        if iscap:
            path = self.base_url + b'/' + path
        else:
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
        return self._get_response(req, False)

    def _post(self, path, data=None, params={}, iscap=False):
        req = self._get_request("POST", path, data=data, params=params, iscap=iscap)
        return self._get_response(req, False)

    def _put(self, path, data=None, params={}, iscap=False):
        req = self._get_request("PUT", path, data=data, params=params, iscap=iscap)
        return self._get_response(req, True)

    def _delete(self, path, params={}, iscap=False):
        req = self._get_request("DELETE", path, params=params, iscap=iscap)
        return self._get_response(req, False)

    def get_info(self, path, iscap=False):
        f = self._get(path, {u't': u'json'}, iscap=iscap)
        try:
            data = json.load(f)
        finally:
            f.close()
        return data

    def get_content(self, path, offset=None, length=None, iscap=False):
        return self._get(path, offset=offset, length=length, iscap=iscap)

    def put_file(self, path, f, iscap=False):
        f = self._put(path, data=f, iscap=iscap)
        try:
            return f.read().decode('utf-8').strip()
        finally:
            f.close()

    def delete(self, path, iscap=False):
        f = self._delete(path, iscap=iscap)
        try:
            return f.read().decode('utf-8').strip()
        finally:
            f.close()

    def mkdir(self, path, iscap=False):
        f = self._post(path, params={u't': u'mkdir'}, iscap=iscap)
        try:
            return f.read().decode('utf-8').strip()
        finally:
            f.close()
