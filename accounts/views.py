from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from .models import User
from .serializers import RegisterSerializer, VerifyOTPSerializer, LoginSerializer
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from .serializers import LogoutSerializer
from rest_framework.generics import GenericAPIView



class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer

class VerifyOTPView(generics.GenericAPIView):
    serializer_class = VerifyOTPSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            user = User.objects.get(email=serializer.validated_data['email'])
            if user.otp_code == serializer.validated_data['otp_code']:
                user.is_verified = True
                user.otp_code = None
                user.save()
                return Response({"detail": "Tasdiqlandi"}, status=status.HTTP_200_OK)
            return Response({"detail": "Xato OTP"}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({"detail": "Foydalanuvchi topilmadi"}, status=status.HTTP_404_NOT_FOUND)

class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = authenticate(email=serializer.validated_data['email'], password=serializer.validated_data['password'])
        if user and user.is_verified:
            refresh = RefreshToken.for_user(user)
            return Response({
                "access": str(refresh.access_token),
                "refresh": str(refresh)
            })
        return Response({"detail": "Login yoki parol xato"}, status=status.HTTP_401_UNAUTHORIZED)




class LogoutView(GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        refresh_token = serializer.validated_data["refresh"]
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "Logout muvaffaqiyatli"}, status=status.HTTP_205_RESET_CONTENT)
        except TokenError:
            return Response({"detail": "Token noto‘g‘ri yoki eskirgan"}, status=status.HTTP_400_BAD_REQUEST)
