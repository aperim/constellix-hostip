"""Connect to the Constellix API
"""

import logging
import hashlib
import hmac
import os
import requests
import base64
import urllib.parse

import util

_CONSTELLIX_APISECRET = os.environ['CONSTELLIX_APISECRET']
"""string: The Constellix API secret

Generated in the Constellix dashboard.
"""

_CONSTELLIX_APIKEY = os.environ['CONSTELLIX_APIKEY']
"""string: The Constellix API key

Generated in the Constellix dashboard.
"""

_DEFAULT_HOST = "api.dns.constellix.com"
_DEFAULT_VERSION = "v1"
_DEFAULT_SERVICE = "domains"
_DEFAULT_TRIES = 8

class Error(Exception):
    """Base class for exceptions in this module."""
    pass

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

    def __init__(self, url, status, message, trace = None, token = None, attempt = None):
        self.url = url
        self.status = url
        self.message = message
        if trace: self.trace = trace
        if token: self.token = token
        if attempt: self.attempt = attempt

class ConstellixAuthentication():
    """Holds authentication information for the API
    
    Args:
        key (string): The Constellix API Key
        secret (string): The Constellix API Secret
    """

    def __init__(self, key, secret):
        super().__init__()
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

    def _send(self, endpoint, data = {}, method = "GET"):
        url = self.url + '/' + str(endpoint)
        method = method.upper()
        payload = {}

        direction = "from"

        if method == "POST" and data:
            payload = data
            direction = "to"
        elif method == "PUT" and data:
            payload = data
            direction = "to"
        elif method == "DELETE" and data:
            payload = data
        elif data:
            url += '?' + urllib.parse.urlencode(data)

        logging.info('[%s] %s', method, url)

        attempt = 1
        while attempt <= self.__tries:
            token = self._getToken()
            headers = {
                'Content-Type': 'application/json',
                'x-cns-security-token': token
            }
            response = requests.request(method, url, headers=headers, json = payload)
            if response.status_code == 200:
                break
            if response.status_code == 400:
                break
            if response.status_code == 404:
                break
            attempt += 1
            logging.debug('[%i] trace: %s', response.status_code,response.headers["X-Trace"])
            logging.debug(response.text)

        if 200 <= response.status_code <= 299:
            return response.json()
        elif response.status_code == 404:
            return
        else:
            raise ConstellixAPIError(url, response.status_code, f'Unable to {method} data {direction} Constellix API.', response.headers["X-Trace"], token, attempt)

        return
    
    def search(self, data = {}, domain_id = None, record_type = None):
        uri = ''
        if domain_id: uri += str(domain_id) + '/'
        if record_type: uri += 'records/' + record_type + '/'
        if isinstance(data, str):
            data = {
                "exact": data
            }
        uri += 'search'
        return self._send(uri, data, "GET")

    def get(self, domain_id, record_type = None, record_id = None):
        uri = str(domain_id)
        if record_type: uri += '/records/' + record_type.upper()
        if record_id: uri += '/' + str(record_id)
        return self._send(uri)

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

