from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from api.permissions import IsTenantMember, IsManagerOrAbove
from api.models import Agent
from api.serializers.agents import AgentSerializer


class AgentViewSet(viewsets.ModelViewSet):
    serializer_class = AgentSerializer
    permission_classes = [IsAuthenticated, IsTenantMember, IsManagerOrAbove]

    def get_queryset(self):
        """Limit agents to the current user's tenant"""
        return Agent.objects.for_user(self.request.user)




    def perform_create(self, serializer):
        """Auto-assign tenant & created_by on create"""
        serializer.save(
            tenant=self.request.user.tenant,
            created_by=self.request.user
        )
