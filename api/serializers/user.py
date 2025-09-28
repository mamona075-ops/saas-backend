
from django.contrib.auth import get_user_model
from rest_framework import serializers


from api.models import Tenant

User = get_user_model()

class UserMeSerializer(serializers.ModelSerializer):
    tenant = serializers.StringRelatedField()  # shows tenant name instead of ID

    class Meta:
        model = User
        fields = ["id", "email", "username", "role", "tenant", "is_active", "is_staff"]


