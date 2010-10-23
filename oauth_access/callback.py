from django.core.urlresolvers import reverse
from django.http import HttpResponse
from django.shortcuts import redirect

from django.contrib.auth import login
from django.contrib.auth.models import User


class Callback(object):
    
    def __call__(self, request, access, token):
        if not request.user.is_authenticated():
            authenticated = False
            user_data = self.fetch_user_data(request, access, token)
            user = self.lookup_user(request, access, user_data)
            if user is None:
                ret = self.handle_no_user(request, access, token, user_data)
                # allow handle_no_user to create a user if need be
                if isinstance(ret, User):
                    user = ret
            else:
                ret = self.handle_unauthenticated_user(request, user, access, token, user_data)
            if isinstance(ret, HttpResponse):
                return ret
        else:
            authenticated = True
            user = request.user
        redirect_to = self.redirect_url(request)
        if user:
            kwargs = {}
            if not authenticated:
                kwargs["identifier"] = self.identifier_from_data(user_data)
            access.persist(user, token, **kwargs)
        return redirect(redirect_to)
    
    def fetch_user_data(self, request, access, token):
        raise NotImplementedError()
    
    def lookup_user(self, request, access, user_data):
        return access.lookup_user(identifier=self.identifier_from_data(user_data))
    
    def redirect_url(self, request):
        raise NotImplementedError()


class AuthenticationCallback(Callback):
    
    def handle_no_user(self, request, access, token, user_data):
        request.session["oauth_signup_data"] = {
            "token": token,
            "user_data": user_data,
        }
        return redirect(
            reverse(
                "oauth_access_finish_signup", kwargs={
                    "service": access.service
                }
            )
        )
    
    def handle_unauthenticated_user(self, request, user, access, token, user_data):
        self.login_user(request, user)
    
    def login_user(self, request, user):
        user.backend = "django.contrib.auth.backends.ModelBackend"
        login(request, user)
