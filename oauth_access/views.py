from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext

from oauth_access.access import OAuthAccess



def oauth_login(request, service):
    access = OAuthAccess(service)
    token = access.unauthorized_token()
    request.session["%s_unauth_token" % service] = token.to_string()
    return HttpResponseRedirect(access.authorization_url(token))


def oauth_callback(request, service):
    ctx = RequestContext(request)
    access = OAuthAccess(service)
    unauth_token = request.session.get("%s_unauth_token" % service, None)
    if unauth_token is None:
        ctx.update({"error": "token_missing"})
    else:
        auth_token = access.check_token(unauth_token, request.GET)
        if auth_token:
            request.session["%s_token" % service] = str(auth_token)
            # @@@ allow other and custom operations here
            return HttpResponseRedirect(reverse("import_contacts"))
        else:
            ctx.update({"error": "token_mismatch"})
    return render_to_response("oauth_access/oauth_error.html", ctx)
