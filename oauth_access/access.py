import cgi
import datetime
import httplib2
import logging
import socket
import urllib
import urlparse

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.urlresolvers import reverse
from django.utils import simplejson as json

from django.contrib.sites.models import Site

import oauth2 as oauth

from oauth_access.exceptions import NotAuthorized, MissingToken
from oauth_access.models import UserAssociation
from oauth_access.utils.anyetree import etree
from oauth_access.utils.loader import load_path_attr


logger = logging.getLogger("oauth_access.access")


class UnknownResponse(Exception):
    pass


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
    
    @property
    def provider_scope(self):
        return self._obtain_setting("endpoints", "provider_scope", False)
    
    def _obtain_setting(self, k1, k2, required=True):
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
            # check this here, because the service key should exist regardless
            if not required:
                return None
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
        parameters = {
            "oauth_callback": self.callback_url,
        }
        client = oauth.Client(self.consumer)
        response, content = client.request(self.request_token_url,
            method = "POST",
            # parameters must be urlencoded (which are then re-decoded by
            # and re-encoded by oauth2 -- seems lame)
            body = urllib.urlencode(parameters),
        )
        if response["status"] != "200":
            raise UnknownResponse(
                "Got %s from %s:\n\n%s" % (
                    response["status"], self.request_token_url, content
                ))
        return oauth.Token.from_string(content)
    
    @property
    def callback_url(self):
        current_site = Site.objects.get(pk=settings.SITE_ID)
        # @@@ http fix
        base_url = "http://%s" % current_site.domain
        callback_url = reverse("oauth_access_callback", kwargs={
            "service": self.service,
        })
        return "%s%s" % (base_url, callback_url)
    
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
        if response["status"] != "200":
            raise UnknownResponse(
                "Got %s from %s:\n\n%s" % (
                    response["status"], self.access_token_url, content
                ))
        return oauth.Token.from_string(content)
    
    def check_token(self, unauth_token, parameters):
        if self.service != "facebook" and unauth_token is None:
            raise MissingToken
        if unauth_token:
            token = oauth.Token.from_string(unauth_token)
            if token.key == parameters.get("oauth_token", "no_token"):
                verifier = parameters.get("oauth_verifier")
                return self.authorized_token(token, verifier)
            else:
                return None
        else:
            code = parameters.get("code")
            if code:
                params = dict(
                    client_id = self.key,
                    redirect_uri = self.callback_url,
                )
                params["client_secret"] = self.secret
                params["code"] = code
                raw_data = urllib.urlopen(
                    "%s?%s" % (
                        self.access_token_url, urllib.urlencode(params)
                    )
                ).read()
                response = cgi.parse_qs(raw_data)
                return OAuth20Token(
                    response["access_token"][-1],
                    int(response["expires"][-1])
                )
            else:
                # @@@ this error case is not nice
                return None
    
    @property
    def callback(self):
        return load_path_attr(self._obtain_setting("endpoints", "callback"))
    
    def authorization_url(self, token=None):
        if token is None:
            # OAuth 2.0
            params = dict(
                client_id = self.key,
                redirect_uri = self.callback_url,
            )
            scope = self.provider_scope
            if scope is not None:
                params["scope"] = ",".join(scope)
            return self.authorize_url + "?%s" % urllib.urlencode(params)
        else:
            request = oauth.Request.from_consumer_and_token(
                self.consumer,
                token = token,
                http_url = self.authorize_url,
            )
            request.sign_request(self.signature_method, self.consumer, token)
            return request.to_url()
    
    def persist(self, user, token, identifier=None):
        expires = hasattr(token, "expires") and token.expires or None
        defaults = {
            "token": str(token),
            "expires": expires,
        }
        if identifier is not None:
            defaults["identifier"] = identifier
        assoc, created = UserAssociation.objects.get_or_create(
            user = user,
            service = self.service,
            defaults = defaults,
        )
        if not created:
            assoc.token = str(token)
            assoc.expires = expires
            assoc.save()
    
    def lookup_user(self, identifier):
        queryset = UserAssociation.objects.all()
        queryset = queryset.select_related("user")
        queryset = queryset.filter(service=self.service)
        try:
            assoc = queryset.get(identifier=identifier)
        except UserAssociation.DoesNotExist:
            return None
        else:
            return assoc.user
    
    def make_api_call(self, kind, url, token, method="GET", **kwargs):
        if isinstance(token, OAuth20Token):
            request_kwargs = dict(method=method)
            if method == "POST":
                params = {
                    "access_token": str(token),
                }
                params.update(kwargs["params"])
                request_kwargs["body"] = urllib.urlencode(params)
            else:
                url += "?%s" % urllib.urlencode(dict(access_token=str(token)))
            http = httplib2.Http()
            response, content = http.request(url, **request_kwargs)
        else:
            if isinstance(token, basestring):
                token = oauth.Token.from_string(token)
            client = Client(self.consumer, token=token)
            # @@@ LinkedIn requires Authorization header which is supported in
            # sub-classed version of Client (originally from oauth2)
            request_kwargs = dict(method=method, force_auth_header=True)
            if method == "POST":
                request_kwargs["body"] = urllib.urlencode(kwargs["params"])
            response, content = client.request(url, **request_kwargs)
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


class Client(oauth.Client):
    """
    Custom client to support forcing Authorization header (which is required
    by LinkedIn). See http://github.com/brosner/python-oauth2/commit/82a05f96878f187f67c1af44befc1bec562e5c1f
    """
    
    def request(self, uri, method="GET", body=None, headers=None,
      redirections=httplib2.DEFAULT_MAX_REDIRECTS, connection_type=None,
      force_auth_header=False):
        
        DEFAULT_CONTENT_TYPE = "application/x-www-form-urlencoded"
        
        if not isinstance(headers, dict):
            headers = {}
        
        is_multipart = method == "POST" and headers.get("Content-Type", DEFAULT_CONTENT_TYPE) != DEFAULT_CONTENT_TYPE
        
        if body and method == "POST" and not is_multipart:
            parameters = dict(urlparse.parse_qsl(body))
        else:
            parameters = None
        
        req = oauth.Request.from_consumer_and_token(self.consumer,
            token=self.token, http_method=method, http_url=uri,
            parameters=parameters)
        
        req.sign_request(self.method, self.consumer, self.token)
        
        if force_auth_header:
            headers.update(req.to_header())
        
        if method == "POST":
            headers["Content-Type"] = headers.get("Content-Type", DEFAULT_CONTENT_TYPE)
            if is_multipart:
                headers.update(req.to_header())
            else:
                if not force_auth_header:
                    body = req.to_postdata()
                else:
                    body = urllib.urlencode(req.get_nonoauth_parameters(), True)
        elif method == "GET":
            if not force_auth_header:
                uri = req.to_url()
        else:
            if not force_auth_header:
                # don't call update twice.
                headers.update(req.to_header())
        
        return httplib2.Http.request(self, uri, method=method, body=body,
            headers=headers, redirections=redirections,
            connection_type=connection_type)


class OAuth20Token(object):
    
    def __init__(self, token, expires=None):
        self.token = token
        if expires is not None:
            self.expires = datetime.datetime.now() + datetime.timedelta(seconds=expires)
        else:
            self.expires = None
    
    def __str__(self):
        return str(self.token)
