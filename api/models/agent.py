from django.db import models
from django.conf import settings
from .tenant import TenantAwareModel

class Agent(TenantAwareModel):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    system_prompt = models.TextField(blank=True, null=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="created_agents",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("tenant", "name")
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.name} ({self.tenant.name})"
