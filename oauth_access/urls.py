from django.conf.urls.defaults import patterns, url

from oauth_access.views import (
    OAuthLoginView, OAuthCallbackView
)


urlpatterns = patterns("",
    url(r"^login/(?P<service>\w+)/$", OAuthLoginView.as_view(), name="oauth_access_login"),
    url(r"^callback/(?P<service>\w+)/$", OAuthCallbackView.as_view(), name="oauth_access_callback"),
)
