from django.shortcuts import redirect
from django.views.generic.base import View

from oauth_access.client import RequestOAuthClient


class OAuthLoginView(View):
    
    def get(self, *args, **kwargs):
        client = RequestOAuthClient(self.request, service=kwargs["service"])
        return redirect(client.authorization_url())


class OAuthCallbackView(View):
    
    def get(self, *args, **kwargs):
        client = RequestOAuthClient(self.request, service=kwargs["service"])
        token = client.authorize()
        return client.callback(token)
