from django.db import models

# class BlacklistedAccessToken(models.Model):
#     jti = models.CharField(max_length=255, unique=True)  # JWT ID
#     created_at = models.DateTimeField(auto_now_add=True)

#     def __str__(self):
#         return self.jti







class BlacklistedAccessToken(models.Model):
    """
    Store blacklisted access token JTI values so the app can reject access tokens immediately.
    - jti: token identifier (unique)
    - created_at: when blacklisted
    - expires_at: optional token expiry (helpful for cleanup)
    """
    jti = models.CharField(max_length=255, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["jti"], name="blacklisted_jti_idx"),
        ]

    def __str__(self):
        return self.jti
