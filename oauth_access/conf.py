from django.conf import settings

from appconf import AppConf

from .utils import load_path_attr


class OAuthAccessAppConf(AppConf):
    
    CALLBACK = "oauth_access.callbacks.dummy"
    
    class Meta:
        prefix = "oauth_access"
    
    def configure_callback(self, value):
        return load_path_attr(value)
