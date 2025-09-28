from django.contrib.auth import authenticate, get_user_model
from rest_framework import serializers
from api.models import Tenant

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    tenant_id = serializers.IntegerField(read_only=True)   # 👈 expose tenant
    role = serializers.CharField(read_only=True)           # 👈 expose role
    class Meta:
        model = User
        fields = ["id", "email", "username", "password", "tenant_id", "role"]

    def create(self, validated_data):
        tenant = Tenant.objects.create(name=f"{validated_data['username']}'s Workspace")
        # tenant, _ = Tenant.objects.get_or_create(name="Default Tenant")
        user = User.objects.create_user(
            email=validated_data["email"],
            username=validated_data["username"],
            password=validated_data["password"],
            tenant=tenant,                # 👈 assign tenant here
            role=User.Role.ADMIN          # 👈 default ADMIN
        )
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = authenticate(
            request=self.context.get("request"),
            email=data.get("email"),
            password=data.get("password"),
        )
        if not user:
            raise serializers.ValidationError("Invalid email or password")
        data["user"] = user
        return data



