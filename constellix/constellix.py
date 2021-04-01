"""Connect to the Constellix API
"""

import logging
import hashlib
import hmac
import os
import requests
import base64
import urllib.parse
import time
from json import JSONDecodeError

import util

_CONSTELLIX_APISECRET = None
"""string: The Constellix API secret

Generated in the Constellix dashboard.
"""
if 'CONSTELLIX_APISECRET' in os.environ: _CONSTELLIX_APISECRET = os.environ['CONSTELLIX_APISECRET']

_CONSTELLIX_APIKEY = None
"""string: The Constellix API key

Generated in the Constellix dashboard.
"""
if 'CONSTELLIX_APIKEY' in os.environ: _CONSTELLIX_APIKEY = os.environ['CONSTELLIX_APIKEY']

_DEFAULT_HOST = "api.dns.constellix.com"
_DEFAULT_VERSION = "v1"
_DEFAULT_SERVICE = "domains"
_DEFAULT_TRIES = 20

_CACHE_GET = {}

class Error(Exception):
    """Base class for exceptions in this module."""
    pass

class MissingKeySecretError(Error):
    """Exception raised if the key or secret is missing for the Constellix API

    Attributes:
        message (str): explanation of the error
    """

    def __init__(self, message):
        super().__init__()
        self.message = message

class ConstellixAPIError(Error):
    """Exception raised for errors with the Constellix API.

    Attributes:
        url (str): the api url
        status (int): the status code returned from the URL
        message (str): explanation of the error
        trace (str): The trace ID from Constellix
        token (str): The token sent to Constellix
        attempt (int): The number of attempts to send this payload
    """

    def __init__(self, url, status, message, trace = None, token = None, failures = None):
        self.url = url
        self.status = url
        self.message = message
        if trace: self.trace = trace
        if token: self.token = token
        if failures: self.failures = failures

class ConstellixAuthentication():
    """Holds authentication information for the API
    
    Args:
        key (string): The Constellix API Key
        secret (string): The Constellix API Secret
    """

    def __init__(self, key, secret):
        super().__init__()
        if not (key and secret):
            raise MissingKeySecretError("The Constellix API Key and Secret must be provided.")
        self.key = key
        self.secret = secret

class api():
    """Communicates with constellix
    """

    def __init__(self, host = _DEFAULT_HOST, version = _DEFAULT_VERSION, service = _DEFAULT_SERVICE, tries = _DEFAULT_TRIES, key = _CONSTELLIX_APIKEY, secret = _CONSTELLIX_APISECRET, verbosity = 0):
        super().__init__()
        self.url = f'https://{host}/{version}/{service}'
        self.__tries = tries
        self.__verbosity = verbosity
        self.__auth = ConstellixAuthentication(key, secret)
        self.__session = requests.Session()

        if self.__verbosity > 3:
            log_level = logging.DEBUG
        elif self.__verbosity > 2:
            log_level = logging.INFO
        elif self.__verbosity > 1:
            log_level = logging.WARNING
        elif self.__verbosity > 0:
            log_level = logging.ERROR
        else:
            log_level = logging.CRITICAL

        logging.basicConfig(level=log_level)

    @property
    def verbosity(self):
        return self.__verbosity

    @verbosity.setter
    def verbosity(self, verbosity):
        verbosity = int(verbosity)
        if verbosity < 0:
            self.__verbosity = 0
        elif verbosity >= 4:
            self.__verbosity = 4
        else:
            self.__verbosity = verbosity

    def _getToken(self):
        key = bytes(self.__auth.secret, 'UTF-8')
        epoch = str(util.epoch())
        message = bytes(epoch, 'UTF-8')
        
        digester = hmac.new(key, message, hashlib.sha1)
        signature1 = digester.digest()
        signature2 = base64.urlsafe_b64encode(signature1)
        hmacdata = str(signature2, 'UTF-8')
        
        return f'{self.__auth.key}:{hmacdata}:{epoch}'

    def _send(self, endpoint, data = {}, method = "GET", use_get_cache = True):
        url = self.url + '/' + str(endpoint)
        method = method.upper()
        payload = {}
        failures = []

        direction = "from"
        cache = False

        if method == "POST" and data:
            payload = data
            direction = "to"
        elif method == "PUT" and data:
            payload = data
            direction = "to"
        elif method == "DELETE" and data:
            payload = data
        elif method == "GET":
            if use_get_cache: cache = True
            if data:
                url += '?' + urllib.parse.urlencode(data)
            if use_get_cache and url in _CACHE_GET:
                logging.info('[CACHE/%s] %s', method, url)
                return _CACHE_GET[url]["json"]
        elif data:
            payload = data

        logging.info('[%s] %s', method, url)
        if payload: logging.debug("Payload: %s", payload)

        attempt = 1
        while attempt <= self.__tries:
            token = self._getToken()
            headers = {
                'Content-Type': 'application/json',
                'x-cns-security-token': token
            }
            
            response = self.__session.request(method, url, headers=headers, json = payload)
            trace = response.headers["X-Trace"] if "X-Trace" in response.headers else 'Unknown'
            remaining = int(response.headers["requestsRemainingHeader"]) if "requestsRemainingHeader" in response.headers else 0
            limit = int(response.headers["requestLimitHeader"]) if "requestLimitHeader" in response.headers else 0
            interval = int(response.headers["requestRefreshInterval"]) if "requestRefreshInterval" in response.headers else 0
            limit_interval = float(response.headers["requestLimitInterval"]) if "requestLimitInterval" in response.headers else 0
            limit_rate = float(response.headers["requestLimitRate"]) if "requestLimitRate" in response.headers else 0
            
            failures.append({
                "attempt": attempt,
                "trace": trace,
                "token": token,
                "status": response.status_code,
                "remaining": remaining,
                "limit": limit,
                "interval": interval,
                "limit_interval": limit_interval,
                "limit_rate": limit_rate
            })

            if response.status_code == 200:
                logging.info('[%i] Requests remaining: %i of %i', response.status_code, remaining, limit)
                break
            if response.status_code == 400:
                break
            if response.status_code == 404:
                break
            
            attempt += 1
            logging.debug('[%i] trace: %s token: %s %s', response.status_code, trace, token, response.text)

        response_data = None

        if 200 <= response.status_code <= 299:
            try:
                response_data = response.json()
            except JSONDecodeError as e:
                logging.warning("Received invalid JSON in response: %s", str(response.content))
                logging.error(e)
        elif response.status_code == 404:
            pass
        else:
            raise ConstellixAPIError(url, response.status_code, f'Unable to {method} data {direction} Constellix API.', response.headers["X-Trace"], token, failures)

        if cache:
            _CACHE_GET[url] = {
                "status": response.status_code,
                "json": response_data,
                "ts": time.time_ns() / (10 ** 9)
            }
            logging.debug("[CACHED] %s = %s", url, _CACHE_GET[url])

        return response_data
    
    def search(self, data = {}, domain_id = None, record_type = None, use_cache = True):
        uri = ''
        if domain_id: uri += str(domain_id) + '/'
        if record_type: uri += 'records/' + record_type + '/'
        if isinstance(data, str):
            data = {
                "exact": data
            }
        uri += 'search'
        return self._send(uri, data, "GET",use_get_cache=use_cache)

    def get(self, domain_id, record_type = None, record_id = None, use_cache = True):
        uri = str(domain_id)
        if record_type: uri += '/records/' + record_type.upper()
        if record_id: uri += '/' + str(record_id)
        return self._send(uri, use_get_cache=use_cache)

    def update(self, domain_id, record_type = None, record_id = None, data = {}):
        uri = str(domain_id)
        if record_type: uri += '/records/' + record_type.upper()
        if record_id: uri += '/' + str(record_id)
        return self._send(uri, data, "PUT")

    def create(self, domain_id, record_type, data = {}):
        record_type = record_type.upper()
        return self._send(f'{domain_id}/records/{record_type}', data, "POST")

    def delete(self, domain_id, record_type = None, record_id = None):
        uri = str(domain_id)
        if record_type: uri += '/records/' + record_type.upper()
        if record_id: uri += '/' + str(record_id)
        return self._send(uri, {}, "DELETE")

    def bulk(self, domain_id, data = None):
        uri = str(domain_id) + '/records'
        if not data:
            return
        return self._send(uri, data, "POST")

