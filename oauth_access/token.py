import urllib

from .models import LinkedToken


class Token(object):
    
    def __init__(self, key, secret):
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
        return LinkedToken.objects.get_or_create(key=key, defaults=dict(token=str(self)))
