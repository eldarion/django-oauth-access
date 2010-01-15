import httplib2
import logging
import socket
import urllib

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.urlresolvers import reverse
from django.utils import simplejson as json

from django.contrib.sites.models import Site

import oauth2 as oauth

from oauth_access.exceptions import NotAuthorized
from oauth_access.utils.anyetree import etree
from oauth_access.utils.loader import load_path_attr


logger = logging.getLogger("oauth_access.access")


class ServiceFail(Exception):
    pass


class OAuthAccess(object):
    
    def __init__(self, service):
        self.service = service
        self.signature_method = oauth.SignatureMethod_HMAC_SHA1()
        self.consumer = oauth.Consumer(self.key, self.secret)
    
    @property
    def key(self):
        return self._obtain_setting("keys", "KEY")
    
    @property
    def secret(self):
        return self._obtain_setting("keys", "SECRET")
    
    @property
    def request_token_url(self):
        return self._obtain_setting("endpoints", "request_token")
    
    @property
    def access_token_url(self):
        return self._obtain_setting("endpoints", "access_token")
    
    @property
    def authorize_url(self):
        return self._obtain_setting("endpoints", "authorize")
    
    def _obtain_setting(self, k1, k2):
        name = "OAUTH_ACCESS_SETTINGS"
        service = self.service
        try:
            return getattr(settings, name)[service][k1][k2]
        except AttributeError:
            raise ImproperlyConfigured("%s must be defined in settings" % (name,))
        except KeyError, e:
            key = e.args[0]
            if key == service:
                raise ImproperlyConfigured("%s must contain '%s'" % (name, service))
            elif key == k1:
                raise ImproperlyConfigured("%s must contain '%s' for '%s'" % (name, k1, service))
            elif key == k2:
                raise ImproperlyConfigured("%s must contain '%s' for '%s' in '%s'" % (name, k2, k1, service))
            else:
                raise
    
    def unauthorized_token(self):
        if not hasattr(self, "_unauthorized_token"):
            self._unauthorized_token = self.fetch_unauthorized_token()
        return self._unauthorized_token
    
    def fetch_unauthorized_token(self):
        current_site = Site.objects.get(pk=settings.SITE_ID)
        # @@@ http fix
        base_url = "http://%s" % (current_site.domain,)
        callback_url = reverse("oauth_access_callback", kwargs={
            "service": self.service,
        })
        parameters = {
            "oauth_callback": "%s%s" % (base_url, callback_url),
        }
        client = oauth.Client(self.consumer)
        response, content = client.request(self.request_token_url,
            method = "POST",
            # parameters must be urlencoded (which are then re-decoded by
            # and re-encoded by oauth2 -- seems lame)
            body = urllib.urlencode(parameters),
        )
        try:
            return oauth.Token.from_string(content)
        except KeyError, e:
            if e.args[0] == "oauth_token":
                raise ServiceFail()
            raise
    
    def authorized_token(self, token, verifier=None):
        parameters = {}
        if verifier:
            parameters.update({
                "oauth_verifier": verifier,
            })
        client = oauth.Client(self.consumer, token=token)
        response, content = client.request(self.access_token_url,
            method = "POST",
            # parameters must be urlencoded (which are then re-decoded by
            # oauth2 -- seems lame)
            body = urllib.urlencode(parameters),
        )
        return oauth.Token.from_string(content)
    
    def check_token(self, unauth_token, parameters):
        token = oauth.Token.from_string(unauth_token)
        if token.key == parameters.get("oauth_token", "no_token"):
            verifier = parameters.get("oauth_verifier")
            return self.authorized_token(token, verifier)
        else:
            return None
    
    def callback(self, *args, **kwargs):
        cb = load_path_attr(self._obtain_setting("endpoints", "callback"))
        return cb(*args, **kwargs)
    
    def authorization_url(self, token):
        request = oauth.Request.from_consumer_and_token(
            self.consumer,
            token = token,
            http_url = self.authorize_url,
        )
        request.sign_request(self.signature_method, self.consumer, token)
        return request.to_url()
    
    def make_api_call(self, kind, url, token, method="GET", **kwargs):
        if isinstance(token, basestring):
            token = oauth.Token.from_string(token)
        client = oauth.Client(self.consumer, token=token)
        response, content = client.request(url, method=method, force_auth_header=True)
        if response["status"] == "401":
            raise NotAuthorized()
        if not content:
            raise ServiceFail("no content")
        logger.debug("response: %r" % response)
        logger.debug("content: %r" % content)
        if kind == "raw":
            return content
        elif kind == "json":
            try:
                return json.loads(content)
            except ValueError:
                # @@@ might be better to return a uniform cannot parse
                # exception and let caller determine if it is service fail
                raise ServiceFail("JSON parse error")
        elif kind == "xml":
            return etree.ElementTree(etree.fromstring(content))
        else:
            raise Exception("unsupported API kind")
