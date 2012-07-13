import urllib
import urlparse

from django.core.exceptions import ImproperlyConfigured
from django.core.urlresolvers import reverse

import requests
import requests.auth

import oauthlib.common
import oauthlib.oauth1.rfc5849

from .conf import settings
from .token import Token
from .utils import load_path_attr


KNOWN_SERVICE_ENDPOINTS = {
    "twitter": {
        "request_token": u"https://api.twitter.com/oauth/request_token",
        "request_auth": u"https://api.twitter.com/oauth/authenticate",
        "access_token": u"https://api.twitter.com/oauth/access_token",
        "api": u"https://api.twitter.com/1",
    },
    "yahoo": {
        "request_token": u"https://api.login.yahoo.com/oauth/v2/get_request_token",
        "access_token": u"https://api.login.yahoo.com/oauth/v2/get_token",
    }
}


class OAuthClient(object):
    
    def __init__(self, **kwargs):
        if "token" in kwargs:
            self.token = kwargs["token"]
            self.service = self.token.service
        else:
            try:
                self.service = kwargs["service"]
            except KeyError:
                raise TypeError("OAuthClient.__init__ takes a service keyword argument")
            else:
                self.token = None
        self.client = self.build_client()
    
    @property
    def key(self):
        return self._get_setting("keys", "KEY")
    
    @property
    def secret(self):
        return self._get_setting("keys", "SECRET")
    
    @property
    def callback_url(self):
        return self._get_setting("endpoints", "callback_url")
    
    @property
    def request_token_url(self):
        return self._get_endpoint_url("request_token")
    
    @property
    def request_auth_url(self):
        return self._get_endpoint_url("request_auth")
    
    @property
    def access_token_url(self):
        return self._get_endpoint_url("access_token")
    
    @property
    def api_url(self):
        return self._get_endpoint_url("api")
    
    def _get_setting(self, k1, k2, required=True):
        name = "OAUTH_ACCESS_SETTINGS"
        service = self.service
        try:
            value = getattr(settings, name)[service][k1][k2]
        except AttributeError:
            raise ImproperlyConfigured("%s must be defined in settings" % (name,))
        except KeyError, e:
            key = e.args[0]
            if key == service:
                raise ImproperlyConfigured("%s must contain '%s'" % (name, service))
            # check this here, because the service key should exist regardless
            if not required:
                return None
            elif key == k1:
                raise ImproperlyConfigured("%s must contain '%s' for '%s'" % (name, k1, service))
            elif key == k2:
                raise ImproperlyConfigured("%s must contain '%s' for '%s' in '%s'" % (name, k2, k1, service))
            else:
                raise
        else:
            return value.decode("utf-8")
    
    def _get_endpoint_url(self, key):
        url = KNOWN_SERVICE_ENDPOINTS.get(self.service, {}).get(key)
        if url is None:
            url = self._obtain_setting("endpoints", key)
        return url
    
    def build_client(self, **extra):
        Client = oauthlib.oauth1.rfc5849.Client
        kwargs = dict(
            client_key=self.key,
            client_secret=self.secret,
        )
        if self.token:
            kwargs["resource_owner_key"] = self.token.key
            kwargs["resource_owner_secret"] = self.token.secret
        else:
            if self.callback_url:
                kwargs["callback_uri"] = self.callback_url
        kwargs.update(extra)
        return Client(**kwargs)
    
    def callback(self, token, func=None):
        if func is None:
            func = settings.OAUTH_ACCESS_CALLBACK
        return func(self, token)
    
    def http_request(self, method, url, **kwargs):
        url = self.api_url + url
        kwargs["auth"] = OAuthClientAuth(self)
        return requests.request(method, url, **kwargs)


class RequestOAuthClient(OAuthClient):
    
    def __init__(self, request, *args, **kwargs):
        self.request = request
        super(RequestOAuthClient, self).__init__(*args, **kwargs)
    
    @property
    def callback_url(self):
        url = self._get_setting("endpoints", "callback_url", required=False)
        if url is None:
            protocol = {True: "https", False: "http"}[self.request.is_secure()]
            host = self.request.get_host()
            path = reverse("oauth_access_callback", kwargs={"service": self.service})
            url = u"%s://%s%s" % (protocol, host, path)
        return url
    
    @property
    def session_oauth_token_key(self):
        return "doa_%s_oauth_token" % self.service
    
    @property
    def session_oauth_authorized_key(self):
        return "doa_%s_oauth_authorized" % self.service
    
    @property
    def session_callback_key(self):
        return "doa_callback_key"
    
    def build_client(self):
        extra = {}
        if self.session_oauth_token_key in self.request.session:
            key, secret = self.request.session.pop(self.session_oauth_token_key)
            extra["resource_owner_key"] = key.decode("utf-8")
            extra["resource_owner_secret"] = secret.decode("utf-8")
        if "oauth_verifier" in self.request.GET:
            extra["verifier"] = self.request.GET["oauth_verifier"].decode("utf-8")
        return super(RequestOAuthClient, self).build_client(**extra)
    
    def callback(self, *args, **kwargs):
        func = None
        if self.session_callback_key in self.request.session:
            func = load_path_attr(self.request.session[self.session_callback_key])
        kwargs.setdefault("func", func)
        return super(RequestOAuthClient, self).callback(*args, **kwargs)
    
    def handle_token_request(self, url):
        # prepare a signed request
        url, headers, body = self.client.sign(url)
        # make the GET request for token
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            raise Exception("non-200 response; got %d: %s" % (response.status_code, response.content))
        # parse the response
        params = dict(urlparse.parse_qsl(response.content))
        # store the token on the request session for Django
        token = (params["oauth_token"], params["oauth_token_secret"])
        self.request.session[self.session_oauth_token_key] = token
        return params
    
    def authorization_url(self):
        params = self.handle_token_request(self.request_token_url)
        if "xoauth_request_auth_url" in params:
            return params["xoauth_request_auth_url"]
        qs = urllib.urlencode({"oauth_token": params["oauth_token"]})
        return "%s?%s" % (self.request_auth_url, qs)
    
    def authorize(self):
        self.handle_token_request(self.access_token_url)
        # mark as authorized (meaning we have an authorized token)
        self.request.session[self.session_oauth_authorized_key] = True
        # rebuild the client to enable HTTP requests to the service
        self.client = self.build_client()
        # create token from ourself
        return Token(self.service, self.client.resource_owner_key, self.client.resource_owner_secret)


class OAuthClientAuth(requests.auth.AuthBase):
    """
    requests authentication class to handle OAuth from oauth_access. Mostly
    copied from requests.auth.
    """
    
    def __init__(self, client):
        self.client = client
    
    def __call__(self, r):
        content_type = r.headers.get("Content-Type")
        decoded_body = oauthlib.common.extract_params(r.data)
        if content_type is None and decoded_body is not None:
            if r.files:
                r.headers["Content-Type"] = "mulitpart/form-encoded"
                r.url, r.headers, _ = self.client.client.sign(
                    unicode(r.full_url), unicode(r.method), None, r.headers
                )
            else:
                r.headers["Content-Type"] = "application/x-www-form-urlencoded"
                r.url, r.headers, r.data = self.client.client.sign(
                    unicode(r.full_url), unicode(r.method), r.data, r.headers
                )
        if unicode("Authorization") in r.headers:
            value = r.headers[unicode("Authorization")].encode("utf-8")
            del r.headers[unicode("Authorization")]
            r.headers["Authorization"] = value
        return r
