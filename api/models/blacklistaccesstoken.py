from django.db import models

class BlacklistedAccessToken(models.Model):
    jti = models.CharField(max_length=255, unique=True)  # JWT ID
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.jti