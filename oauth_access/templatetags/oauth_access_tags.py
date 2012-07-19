from django import template

from oauth_access.token import Token


register = template.Library()


@register.filter
def authed_via(user, service):
    if user.is_authenticated():
        token = Token.lookup(service, user)
        return token is not None and not token.expired()
    else:
        return False
