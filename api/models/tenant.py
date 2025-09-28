from django.db import models

class TenantQuerySet(models.QuerySet):
    def for_user(self, user):
        """Filter records for the user's tenant"""
        if not user or not getattr(user, "tenant_id", None):
            return self.none()
        return self.filter(tenant_id=user.tenant_id)


class TenantManager(models.Manager):
    def get_queryset(self):
        return TenantQuerySet(self.model, using=self._db)

    def for_user(self, user):
        return self.get_queryset().for_user(user)


class Tenant(models.Model):
    name = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class TenantAwareModel(models.Model):
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="%(class)ss")

    objects = TenantManager()

    class Meta:
        abstract = True
