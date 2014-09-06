from urllib2 import Request, urlopen, quote, HTTPError
import json


class TahoeError(IOError):
    pass


class TahoeConnection(object):
    def __init__(self, base_url, rootcap):
        assert isinstance(base_url, unicode)
        assert isinstance(rootcap, unicode)
        self.base_url = (base_url.rstrip('/') + '/uri/' + rootcap).encode('utf-8')

    def _url(self, path, params={}):
        assert isinstance(path, unicode), path

        path = path.encode('utf-8')
        path = quote(path).lstrip(b'/')

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

        return self.base_url + b'/' + path

    def _get_request(self, method, path, offset=None, length=None, data=None, params={}):
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

        req = Request(self._url(path, params),
                      data=data,
                      headers=headers)
        req.get_method = lambda: method
        return req

    def _get(self, path, params={}, offset=None, length=None):
        req = self._get_request("GET", path, params=params, offset=offset, length=length)
        return urlopen(req)

    def _post(self, path, data=None, params={}):
        req = self._get_request("POST", path, data=data, params=params)
        return urlopen(req)

    def _put(self, path, data=None, params={}):
        req = self._get_request("PUT", path, params=params)
        return urlopen(req)

    def _delete(self, path, params={}):
        req = self._get_request("DELETE", path, params=params)
        return urlopen(req)

    def get_info(self, path):
        f = self._get(path, {u't': u'json'})
        data = json.load(f)
        return data

    def get_content(self, path, offset=None, length=None):
        f = self._get(path, offset=offset, length=length)
        return f


class TahoeIO(object):
    def __init__(self, base_url, rootcap):
        self.connection = TahoeConnection(base_url, rootcap)

    def listdir(self, path):
        try:
            info = self.connection.get_info(path)
        except HTTPError, e:
            raise TahoeError(e)

        return info[1][u'children'].keys()

    
