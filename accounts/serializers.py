from rest_framework import serializers
from .models import User
from .utils import generate_otp, send_otp_email

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        password = validated_data.pop('password')
        otp = generate_otp()
        user = User.objects.create(**validated_data, otp_code=otp, is_verified=False)
        user.set_password(password)
        user.save()
        send_otp_email(user.email, otp)
        return user

class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp_code = serializers.CharField(max_length=6)

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)