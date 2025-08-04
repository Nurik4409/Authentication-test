import random
from django.core.mail import send_mail

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(email, otp_code):
    subject = "Tasdiqlash kodingiz"
    message = f"Sizning OTP kodingiz: {otp_code}"
    from_email = "noreply@example.com"
    recipient_list = [email]
    send_mail(subject, message, from_email, recipient_list)