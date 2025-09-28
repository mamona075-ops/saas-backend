from rest_framework.permissions import BasePermission

class IsTenantMember(BasePermission):
    """User must belong to a tenant."""
    def has_permission(self, request, view):
        return bool(
            request.user
            and request.user.is_authenticated
            and getattr(request.user, "tenant", None) is not None
        )


class IsAdmin(BasePermission):
    """Tenant-level Admin check (role-based)."""
    def has_permission(self, request, view):
        return bool(
            request.user 
            and request.user.is_authenticated 
            and getattr(request.user, "role", None) == "ADMIN"
        )


class IsManagerOrAbove(BasePermission):
    """Allow Admin or Manager role."""
    def has_permission(self, request, view):
        return bool(
            request.user 
            and request.user.is_authenticated 
            and getattr(request.user, "role", None) in ("ADMIN", "MANAGER")
        )


class IsOwnerOrAdmin(BasePermission):
    """
    Object-level: Allow if same tenant or Admin.
    Works if object has tenant or user field.
    """
    def has_object_permission(self, request, view, obj):
        if getattr(request.user, "role", None) == "ADMIN":
            return True

        tenant = getattr(obj, "tenant", None)
        owner_user = getattr(obj, "user", None)

        if tenant:
            return tenant == getattr(request.user, "tenant", None)
        if owner_user:
            return owner_user == request.user

        return False
