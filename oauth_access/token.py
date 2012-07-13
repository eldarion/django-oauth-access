import urllib
import urlparse

from django.db import models

from .models import LinkedToken


class Token(object):
    
    @classmethod
    def lookup(cls, service, key):
        if isinstance(key, models.Model):
            key = "model:%s:%s" % (str(key._meta), key.pk)
        try:
            linked_token = LinkedToken.objects.get(service=service, key=key)
        except LinkedToken.DoesNotExist:
            return None
        data = dict(urlparse.parse_qsl(linked_token.token))
        return cls(service, data["key"], data["secret"])
    
    def __init__(self, service, key, secret):
        self.service = service
        self.key = key
        self.secret = secret
        self.expires = None
    
    def __str__(self):
        params = {
            "key": self.key,
            "secret": self.secret,
        }
        return urllib.urlencode(params)
    
    def link(self, key):
        if isinstance(key, models.Model):
            key = "model:%s:%s" % (str(key._meta), key.pk)
        return LinkedToken.objects.get_or_create(
            service=self.service, key=key,
            defaults=dict(token=str(self))
        )
