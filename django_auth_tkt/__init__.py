from auth_tkt import ticket as auth_tkt
from datetime import timedelta
from django.conf import settings
from django.contrib import auth as django_auth
from django.contrib.auth.middleware import RemoteUserMiddleware
from django.contrib.auth.backends import RemoteUserBackend
from django.core.exceptions import ImproperlyConfigured
from functools import wraps


__all__ = ('auth', 'unauth', 'SsoMiddleware')

__version__ = '0.1.0'

# See: https://github.com/yola/auth_tkt/
TICKET_NAME = getattr(settings, 'SSO_TICKET_NAME', 'auth_tkt')

# Ticket expiry setting for mod_auth_tkt does not seem to work,
# make certain that the auth cookie expires
TICKET_LIFETIME = getattr(settings, 'SSO_TICKET_LIFETIME', timedelta(hours=1))

# Hash algorithm, can be one of 'md5' (default), 'sha256' or 'sha512'
HASH_ALGORITHM = getattr(settings, 'SSO_HASH_ALGORITHM', 'md5')


# HTTP redirect status codes
TEMPORARY_REDIRECT_CODES = (302, 303, 307)


def guess_client_ip(request):
    'Choose the most likely client IP from request headers'
    ip = (request.META.get('HTTP_X_FORWARDED_FOR',
            request.META.get('REMOTE_ADDR', ''))).split(',')[0].strip()
    # mod_auth_tkt chokes on IIPv6, fake it
    return ip if ':' not in ip else '0.0.0.0'
    

def auth(view):
    'Decorator to add an SSO ticket to the Django login'
    @wraps(view)
    def wrapped(request, *args, **kw):
        response = view(request, *args, **kw)
        if response.status_code not in TEMPORARY_REDIRECT_CODES: return response
        
        # Try to get the client IP
        ip = guess_client_ip(request)

        # Use Django group names as auth tokens
        tokens = [g.name for g in request.user.groups.all()]

        # Create an SSO auth ticket
        tkt = auth_tkt.AuthTkt(settings.SECRET_KEY, request.user.username,
            ip=ip, tokens=tokens, digest=HASH_ALGORITHM)

        # Set auth cookie
        c = tkt.cookie(TICKET_NAME, secure=True, httponly=True)
        expiry = TICKET_LIFETIME.total_seconds()
        if expiry: c[TICKET_NAME]['Max-Age'] = expiry
        response['Set-Cookie'] = c.output(header='').strip()
        return response
    return wrapped


def unauth(view):
    'Decorator to clear the SSO ticket on Django logout'
    @wraps(view)
    def wrapped(request, *args, **kw):
        response = view(request, *args, **kw)
        response['Set-Cookie'] = '%s=invalid; Path=/; Max-Age=0' % TICKET_NAME
        return response
    return wrapped


class SsoMiddleware(RemoteUserMiddleware):
    """
    Middleware for auth_tkt authentication.

    If request.user is not authenticated, then this middleware attempts to
    authenticate the username via an authentication ticket.
    If authentication is successful, the user is automatically logged in to
    persist the user in the session.

    Log out the Django user if te SSO ticket is not present.
    """

    def process_request(self, request):
        # AuthenticationMiddleware is required so that request.user exists.
        if not hasattr(request, 'user'):
            raise ImproperlyConfigured(
                "The Django remote user auth middleware requires the"
                " authentication middleware to be installed.  Edit your"
                " MIDDLEWARE setting to insert"
                " 'django.contrib.auth.middleware.AuthenticationMiddleware'"
                " before the SsoMiddleware class.")

        ticket = auth_tkt.validate(request.COOKIES.get(TICKET_NAME, ''),
            settings.SECRET_KEY,
            ip=guess_client_ip(request),
            timeout=int(TICKET_LIFETIME.total_seconds()),
            digest=HASH_ALGORITHM)

        if not ticket:
            if request.user.is_authenticated:
                django_auth.logout(request)
            return

        # If the user is already authenticated and that user is the user we are
        # getting passed in the headers, then the correct user is already
        # persisted in the session and we don't need to continue.
        if request.user.is_authenticated:
            if request.user.get_username() == self.clean_username(ticket.uid, request):
                return
            else:
                # An authenticated user is associated with the request, but
                # it does not match the authorized user in the header.
                django_auth.logout(request)

        # We are seeing this user for the first time in this session,
        # attempt to authenticate the user if RemoteUserBackend is configured.
        if 'django.contrib.auth.backends.RemoteUserBackend' in settings.AUTHENTICATION_BACKENDS:
            user = django_auth.authenticate(request, remote_user=ticket.uid)
            if user:
                # User is valid.  Set request.user and persist user in the session
                # by logging the user in.
                request.user = user
                django_auth.login(request, user)
