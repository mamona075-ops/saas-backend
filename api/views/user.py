from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from api.serializers.user import UserMeSerializer
from rest_framework import generics


class UserMeView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserMeSerializer(request.user)
        return Response({
            "status": "success",
            "data": {"user": serializer.data},
            "message": "User info retrieved successfully"
        })
