from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

# Optional: JWT built-in views (only if you want them for debugging)
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from api.views.user import UserMeView
from api.views.agents import AgentViewSet
from api.views.auth import (
    RegisterView,
    LoginView,
    LogoutView,
)


from api.serializers.token import (
    CustomTokenObtainPairSerializer,
    CustomTokenRefreshSerializer,
)



class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


class CustomTokenRefreshView(TokenRefreshView):
    serializer_class = CustomTokenRefreshSerializer



class NotFoundView(APIView):
    def get(self, request, *args, **kwargs):
        return Response(
            {"detail": "342 Not Found - Please check the URL or try /api/auth/login/"},
            status=status.HTTP_404_NOT_FOUND,
        )


# DRF Router
router = DefaultRouter()
router.register(r"agents", AgentViewSet, basename="agent")
urlpatterns = [
    path('admin/', admin.site.urls),

    # Auth endpoints (custom flow)
    path("api/auth/register/", RegisterView.as_view(), name="register"),
    path("api/auth/login/", LoginView.as_view(), name="login"),
    path("api/auth/me/", UserMeView.as_view(), name="user-me"), 
    path("api/auth/logout/", LogoutView.as_view(), name="logout"),

    path("api/auth/token/", CustomTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/auth/token/refresh/", CustomTokenRefreshView.as_view(), name="token_refresh"),

    path("api/", include(router.urls)),
    path("", NotFoundView.as_view(), name="not-found"),

]
