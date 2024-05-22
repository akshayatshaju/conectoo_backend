from django.core.mail import send_mail

import random
from django.conf import settings
from .models import Account
from django.shortcuts import get_object_or_404

def send_otp_via_email(subject, message, from_email, recipient_list):
    send_mail(subject, message, from_email, recipient_list)
    
    
def set_otp_via_email(email):
    subject = "Account Verification email"
    otp = random.randint(1000, 9999)
    message = f'Your otp is {otp}'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    
     # Corrected the function call to send_otp_via_email
    send_otp_via_email(subject, message, email_from, recipient_list)

    user_obj = get_object_or_404(Account, email=email)
    user_obj.otp = otp
    user_obj.save()