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
    url(
        regex = r"^finish_signup/(?P<service>\w+)/$",
        view = "oauth_access.views.finish_signup",
        name = "oauth_access_finish_signup"
    )
)