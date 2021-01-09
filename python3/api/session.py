# coding:utf-8
import os
import base64
import datetime
import hashlib
import hmac
import urllib.request, urllib.parse, urllib.error
import urllib.parse
import pytz
import requests


class ScalrApiSession(requests.Session):
    def __init__(self, client):
        self.client = client
        super(ScalrApiSession, self).__init__()

    def prepare_request(self, request):
        if not request.url.startswith(self.client.api_url):
            request.url = "".join([self.client.api_url, request.url])
        request = super(ScalrApiSession, self).prepare_request(request)

        now = datetime.datetime.now(tz=pytz.timezone(os.environ.get("TZ", "UTC")))
        date_header = now.isoformat()

        url = urllib.parse.urlparse(request.url)

        # TODO - Spec isn't clear on whether the sorting should happen prior or after encoding
        if url.query:
            pairs = urllib.parse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True)
            pairs = [list(map(urllib.parse.quote, pair)) for pair in pairs]
            pairs.sort(key=lambda pair: pair[0])
            canon_qs = "&".join("=".join(pair) for pair in pairs)
        else:
            canon_qs = ""

        # Authorize
        sts = "\n".join([
            request.method,
            date_header,
            url.path,
            canon_qs,
            request.body if request.body is not None else ""
        ])

        sig = " ".join([
            "V1-HMAC-SHA256",
            base64.b64encode(hmac.new(bytes(self.client.key_secret, 'utf-8'), bytes(sts, 'utf-8'), hashlib.sha256).digest()).decode('utf-8')
        ])

        request.headers.update({
            "X-Scalr-Key-Id": self.client.key_id,
            "X-Scalr-Signature": sig,
            "X-Scalr-Date": date_header,
            "X-Scalr-Debug": "1"
        })

        self.client.logger.debug("URL: %s", request.url)
        self.client.logger.debug("StringToSign: %s", repr(sts))
        self.client.logger.debug("Signature: %s", repr(sig))

        return request

    def request(self, *args, **kwargs):
        res = super(ScalrApiSession, self).request(*args, **kwargs)
        self.client.logger.info("%s - %s", " ".join(args), res.status_code)
        try:
            errors = res.json().get("errors", None)
            if errors is not None:
                for error in errors:
                    self.client.logger.warning("API Error (%s): %s", error["code"], error["message"])
        except ValueError:
            self.client.logger.error("Received non-JSON response from API!")
        res.raise_for_status()
        self.client.logger.debug("Received response: %s", res.text)
        return res
