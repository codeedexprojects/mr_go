# utils.py

import random
from django.core.mail import send_mail

def generate_unique_tracking_id():
    random_number = random.randint(100000, 999999)
    tracking_id = f"MR{random_number}"
    return tracking_id

# utils.py

import random
import string

def generate_unique_invoice_number():
    """Generate a unique invoice number."""
    prefix = "INV"  # Prefix for the invoice number
    length = 8  # Length of the random part of the invoice number
    characters = string.digits  # Characters to choose from for the random part
    # Generate a random string of digits for the invoice number
    random_part = ''.join(random.choices(characters, k=length))
    # Concatenate prefix and random part to form the invoice number
    invoice_number = f"{prefix}{random_part}"
    return invoice_number


def generate_otp():
    return str(random.randint(1000, 9999))

def send_otp_email(to_email, otp):
    subject = 'Account Registration OTP'
    message = f'Your OTP for account registration is: {otp}'
    from_email = 'praveen.codeedex@gmail.com'  # Replace with your email
    recipient_list = [to_email]

    send_mail(subject, message, from_email, recipient_list)
    

