from django.db import models
from .tenant import Tenant

class Subscription(models.Model):
    tenant = models.OneToOneField(
        Tenant, on_delete=models.CASCADE, related_name="subscription"
    )
    plan = models.CharField(max_length=50, default="free")
    stripe_customer_id = models.CharField(max_length=255, blank=True, null=True)
    active = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.tenant.name} - {self.plan}"
