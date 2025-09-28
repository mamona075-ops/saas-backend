from django.core.management.base import BaseCommand
from django.utils import timezone

from api.models import BlacklistedAccessToken


class Command(BaseCommand):
    help = "Delete expired entries from BlacklistedAccessToken (expires_at <= now)"

    def handle(self, *args, **options):
        now = timezone.now()
        qs = BlacklistedAccessToken.objects.filter(expires_at__isnull=False, expires_at__lte=now)
        count = qs.count()
        qs.delete()
        self.stdout.write(self.style.SUCCESS(f"Deleted {count} expired blacklisted tokens"))