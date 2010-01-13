from django.conf.urls.defaults import *



urlpatterns = patterns("",
    url(
        regex = r"^login/(?P<service>\w+)/$",
        view = "oauth_access.views.oauth_login",
        name = "oauth_access_login",
    ),
    url(
        regex = r"^callback/(?P<service>\w+)/$",
        view = "oauth_access.views.oauth_callback",
        name = "oauth_access_callback"
    ),
)