# `django-auth-tkt`, a Django SSO authentication provider

## Introduction

This tiny module adds [mod_auth_tkt](http://www.openfusion.com.au/labs/mod_auth_tkt/) login support to a [Django](https://djangoproject.com/) site. Whenever a user logs in to Django, an additional SSO ticket is created that can be used to also access other authenticated URLs outside of Django.

As a convenience, the names of all groups to which the logged in user belongs to are added to the `token` list of the SSO ticket. This can be used for `TKTAuthToken` access control.

It does not add any authentication backend, you can use either the included `ModelBackend` or any other that works with Django's `AuthenticationMiddleware`.

The lifetime of tickets can be configured in the Django `settings.py`. When the user logs out of Django, the ticket is also invalidated.

## Usage

Add `git+https://github.com/dnknth/django-auth-tkt.git` to `requirements.txt`.

In `settings.py`:

 * Optionally (but recommended), add `django_auth_tkt.SsoMiddleware` to the `MIDDLEWARE` list. It logs out the current user from Django when teh SSO ticket expires and relies on `django.contrib.auth.middleware.AuthenticationMiddleware`, so it should be placed below it.
 * Also optionally, define the lifetime of tickets, e.g. `SSO_TICKET_LIFETIME = timedelta(days=1)`. The default value is one hour.
 * The default cookie name of the ticket is `auth_tkt`, it can be changed with the `SSO_TICKET_NAME` setting.
 * The default hash algorithm is SHA256. It can be adjusted with `SSO_HASH_ALGORITHM`, 
   allowed values are `'md5'` [(insecure)](https://security.stackexchange.com/a/19908), `'sha256'` and `'sha512'`.
 
Decorate the [authentication views](https://docs.djangoproject.com/en/4.0/topics/auth/default/#module-django.contrib.auth.views) in the main `urls.py`, for example:

    from django.contrib import admin
    from django.contrib.auth import views as auth_views
    from django.urls import include, path
    import django_auth_tkt as sso

    urlpatterns = [
        path('accounts/login/', sso.auth(auth_views.LoginView.as_view(
            redirect_authenticated_user=True))),
        path('accounts/logout/', sso.unauth(auth_views.LogoutView.as_view())),
        path('accounts/', include('django.contrib.auth.urls')),
    
        path('admin/login/', sso.auth(admin.site.login)),
        path('admin/logout/', sso.unauth(admin.site.logout)),
        path('admin/', admin.site.urls),
    ]

For Apache configuration examples, see [mod_auth_tkt(3)](http://manpages.ubuntu.com/manpages/focal/en/man3/mod_auth_tkt.3.html#examples).
