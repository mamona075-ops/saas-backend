from rest_framework import serializers
from api.models import Agent


class AgentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Agent
        fields = [
            "id",
            "tenant",
            "name",
            "description",
            "system_prompt",
            "created_by",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_by", "created_at", "updated_at", "tenant"]


    def validate_name(self, value):
        user = self.context["request"].user
        if Agent.objects.filter(tenant=user.tenant, name=value).exists():
            raise serializers.ValidationError("Agent with this name already exists in your workspace.")
        return value

    def create(self, validated_data):
        user = self.context["request"].user
        validated_data["tenant"] = user.tenant
        validated_data["created_by"] = user
        return super().create(validated_data)
