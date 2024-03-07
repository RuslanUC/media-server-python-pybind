from ._pymedooze import *
from ._pymedooze import MediaServer as MediaServerNative
from .endpoint import Endpoint
from .transport import Transport


class MediaServer(MediaServerNative):
    _endpoints = set()

    @classmethod
    def create_endpoint(cls, ip: str) -> Endpoint:
        endpoint_ = Endpoint(ip)
        cls._endpoints.add(endpoint_)

        return endpoint_
