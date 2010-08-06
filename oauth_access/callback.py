from django.shortcuts import redirect


class AuthenticationCallback(object):
    
    def __call__(self, request, access, token):
        if not request.user.is_authenticated():
            user_data = self.fetch_user_data(request, access, token)
            user = self.lookup_user(request, access, user_data)
            if user is None:
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
            else:
                user.backend = "django.contrib.auth.backends.ModelBackend"
                login(request, user)
        else:
            user = request.user
        redirect_to = self.redirect_url()
        access.persist(user, token)
        return redirect(redirect_to)
    
    def redirect_url(self, request):
        raise NotImplementedError()
    
    def lookup_user(self, request, access, user_data):
        return access.lookup_user(identifier=self.identifier_from_data(user_data))
