import urllib
import urlparse

from django.core.exceptions import ImproperlyConfigured
from django.core.urlresolvers import reverse

import requests

import oauthlib.oauth1.rfc5849

from .conf import settings
from .token import Token
from .utils import load_path_attr


KNOWN_SERVICE_ENDPOINTS = {
    "twitter": {
        "request_token": u"https://api.twitter.com/oauth/request_token",
        "request_auth": u"https://api.twitter.com/oauth/authenticate",
        "access_token": u"https://api.twitter.com/oauth/access_token",
    },
    "yahoo": {
        "request_token": u"https://api.login.yahoo.com/oauth/v2/get_request_token",
        "access_token": u"https://api.login.yahoo.com/oauth/v2/get_token",
    }
}


class OAuthClient(object):
    
    def __init__(self, service, token=None):
        self.service = service
        self.token = token
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
        if self.callback_url:
            kwargs["callback_uri"] = self.callback_url
        if self.token:
            kwargs["resource_owner_key"] = token.key
            kwargs["resource_owner_secret"] = token.secret
        kwargs.update(extra)
        return Client(**kwargs)
    
    def callback(self, token, func=None):
        if func is None:
            func = settings.OAUTH_ACCESS_CALLBACK
        return func(self, token)
    
    def http_request(self, url):
        # @@@ sign requires the body to build a signature. this is going to
        # be problematic with requests (need to work out how to accomplish
        # this for POST/PUT requests)
        url, headers, body = self.client.sign(url)


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
        return Token(self.client.resource_owner_key, self.client.resource_owner_secret)
