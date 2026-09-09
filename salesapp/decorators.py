from functools import wraps
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied


def role_required(*allowed_roles):
    """Only allow the view if the logged-in user's profile role is in allowed_roles.
    Admin and IT (is_full_access) are always allowed, regardless of allowed_roles."""
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def wrapped(request, *args, **kwargs):
            profile = getattr(request.user, 'profile', None)
            if profile is None:
                raise PermissionDenied('Your account does not have access to this page.')
            if profile.is_full_access or profile.role in allowed_roles:
                return view_func(request, *args, **kwargs)
            raise PermissionDenied('Your account does not have access to this page.')
        return wrapped
    return decorator
