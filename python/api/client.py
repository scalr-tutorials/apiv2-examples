# coding:utf-8
from collections import Mapping, Iterable
import logging
import random
import hashlib

from api.session import ScalrApiSession


# Not implemented yet Scalr-side
FUZZ_PROBABILITY = 0


def _update_hash(o, h):
    if isinstance(o, Mapping):
        for k, v in sorted(o.items()):
            h.update(str(k))
            _update_hash(v, h)
    elif isinstance(o, Iterable):
        for v in sorted(o):
            h.update(str(v))
    else:
        h.update(str(o))


class ScalrApiClient(object):
    def __init__(self, api_url, key_id, key_secret):
        self.api_url = api_url
        self.key_id = key_id
        self.key_secret = key_secret
        self.logger = logging.getLogger("api[{0}]".format(self.api_url))
        self.logger.addHandler(logging.StreamHandler())
        self.session = ScalrApiSession(self)

    def list(self, path, **kwargs):
        data = []
        ident = False
        while path is not None:
            if ident:
                print
            body = self.session.get(path, **kwargs).json()
            data.extend(body["data"])
            path = body["pagination"]["next"]
            ident = True
        return data

    def create(self, *args, **kwargs):
        self._fuzz_ids(kwargs.get("json", {}))
        return self.session.post(*args, **kwargs).json().get("data")

    def fetch(self, *args, **kwargs):
        return self.session.get(*args, **kwargs).json()["data"]

    def delete(self, *args, **kwargs):
        self.session.delete(*args, **kwargs)

    def post(self, *args, **kwargs):
        return self.session.post(*args, **kwargs).json()["data"]
    
    def patch(self, *args, **kwargs):
        return self.session.patch(*args, **kwargs).json()["data"]

    def _fuzz_ids(self, data):
        """
        Random but predictable fuzzing to use bare IDs.
        Whether or not we fuzz the IDs in a given request is predictable,
        """
        h = hashlib.sha256()
        _update_hash(data, h)

        rng = random.Random()
        rng.seed(h.digest())

        for k, v in list(sorted(data.items())):
            if not isinstance(v, dict):
                continue
            # TODO - Exclusions
            if rng.random() < FUZZ_PROBABILITY:
                id_ = v["id"]
                data[k] = id_
                self.logger.warning("Using bare ID for `%s` (ID: `%s`)", k, id_)
