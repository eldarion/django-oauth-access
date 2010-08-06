from django import template

from oauth_access.models import UserAssociation


register = template.Library()


@register.filter
def authed_via(user, service):
    if user.is_authenticated():
        try:
            assoc = UserAssociation.objects.get(user=user, service=service)
        except UserAssociation.DoesNotExist:
            return False
        return assoc.expired()
    else:
        return False
