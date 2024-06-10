import datetime
import random
import requests
from bs4 import BeautifulSoup
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import BaseUserManager,AbstractBaseUser
from django.core.exceptions import ObjectDoesNotExist
from django.db import models
from django.utils import timezone
from datetime import datetime



class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        username = extra_fields.pop('username', None)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    mobile = models.CharField(max_length=15, null=True, blank=True, unique=True)
    full_name = models.CharField(max_length=150, null=True, blank=True)
    username = models.CharField(max_length=40, null=True, blank=True)
    primary_address = models.CharField(max_length=250, null=True, blank=True)
    secondary_address = models.CharField(max_length=250, null=True, blank=True)
    city = models.CharField(max_length=30, null=True, blank=True)
    state = models.CharField(max_length=20, null=True, blank=True)
    pincode = models.IntegerField(null=True, blank=True)
    business_name = models.CharField(max_length=50, null=True, blank=True)
    business_details = models.CharField(max_length=250, null=True, blank=True)
    otp_secret_key = models.CharField(max_length=32, blank=True, null=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email


class Contactus(models.Model):
    Name = models.CharField(max_length=30, null=False, blank=True)
    Email = models.EmailField(null=False, blank=True)
    Mobile = models.IntegerField(null=True, blank=True)
    Message = models.CharField(max_length=3000, null=False, blank=True)


class ShippingRegistration(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=False)
    Shipping_choices = [
        ('TRACKON', 'TRACKON'),
        ('DTDC', 'DTDC'),
        ('SPEED POST', 'SPEED POST'),
        ('PROFESSIONAL', 'PROFESSIONAL'),
    ]
    Shipping_Through = models.CharField(max_length=15, choices=Shipping_choices,null=True)
    Reciepient_Name = models.CharField(max_length=20, blank=False)
    Mobile = models.IntegerField(blank=False)
    Pin_Code = models.IntegerField(blank=False)
    City = models.CharField(max_length=50, blank=True, null=True)
    Address = models.CharField(max_length=250, blank=True)
    Consignment_Choices = [
        ('Document', 'Document'),
        ('Non-Document', 'Non-Document'),
    ]
    Consignment = models.CharField(max_length=20, blank=True, null=True, choices=Consignment_Choices)
    ContentType_Choices = [
        ('ARTIFICIAL JWELLERY', 'ARTIFICIAL JWELLERY'),
        ('BAGS', 'BAGS'),
        ('BOOKS', 'BOOKS'),
        ('CLOTHING', 'CLOTHING'),
        ('CORPORATE GIFTS (EG:MOMENTOES/WOODEN PLAQUES)', 'CORPORATE GIFTS (EG:MOMENTOES/WOODEN PLAQUES)'),
        ('LUGGAGE', 'LUGGAGE'),
        ('PERFUMES', 'PERFUMES'),
        ('PHOTO FRAME', 'PHOTO FRAME'),
        ('RAKHI', 'RAKHI'),
        ('SHOES', 'SHOES'),
        ('SLIPPERS', 'SLIPPERS'),
    ]
    Content_Type = models.CharField(max_length=200, blank=True, null=True, choices=ContentType_Choices)
    Number_of_box = models.CharField(max_length=20, blank=True, null=True)
    Declared_value = models.CharField(max_length=20, blank=True, null=True)
    Booking_date = models.DateField(auto_now_add=True)
    Delivery_date = models.DateField(null=True)
    tracking_id = models.CharField(max_length=50, unique=True, null=True, blank=True)
    third_party_tracking_id = models.CharField(max_length=50, blank=True, null=True)

    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('ACCEPTED', 'Accepted'),
        ('REJECTED', 'Rejected'),
    ]
    registration_status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING', blank=True,null=True)
    Price_per_kg = models.FloatField(null=True, blank=True , default='0')
    Total_weight = models.FloatField(null=True, blank=True, default='0')
    Total_price = models.FloatField(null=True, blank=True,default='0')
    packing = models.FloatField(null=True, blank=True,default='0')
    packing_cover = models.FloatField(null=True, blank=True,default='0')
    invoice_number = models.CharField(max_length=20,  null=True, editable=False,default='0')
    final_amount = models.FloatField(null=True,blank=True,default='0')

    PAYMENT_CHOICES = [
        ('Collected', 'Collected'),
        ('Not Collected', 'Not Collected'),
    ]
    payment_status = models.CharField(max_length=20, choices=PAYMENT_CHOICES, blank=True, null=True)

    



    def fetch_city(self):
        api_url = f"http://postalpincode.in/api/pincode/{self.Pin_Code}"
        try:
            response = requests.get(api_url)
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict) and 'PostOffice' in data and data['PostOffice']:
                    cities = [office.get('District') for office in data['PostOffice'] if office.get('District')]
                    if cities:
                        self.City = ', '.join(cities)
                        self.save(update_fields=['City'])
        except requests.exceptions.RequestException as e:
            print(f"Error fetching city for pin code {self.Pin_Code}: {e}")

    def get_shipment_updates(self):
        try:
            # Get the appropriate URL pattern based on the courier service
            courier_urls = {
                "DTDC": "https://www.dtdc.in/tracking.asp?ref_no={third_party_tracking_id}",
                # Add other courier services and their URLs here
            }
            courier_url = courier_urls.get(self.Shipping_Through)
            if not courier_url:
                return "Invalid courier service specified."

            # Construct the complete tracking URL
            tracking_url = courier_url.format(third_party_tracking_id=self.third_party_tracking_id)

            # Fetch the tracking page HTML using the constructed URL
            response = requests.get(tracking_url)
            response.raise_for_status()  # Raise an exception for HTTP errors
            html_content = response.text

           
            print(html_content)

           
            soup = BeautifulSoup(html_content, "html.parser")
            status = soup.find("span", class_="shipment-status").text
            location = soup.find("div", class_="location").text
            
            
            self.status = status
            self.last_update_timestamp = timezone.now()
            

            self.save()

            tracking_status, created = TrackingStatus.objects.get_or_create(product=self)
            current_time = timezone.now()

            if status == 'Placed':
                tracking_status.status = 'Placed'
                tracking_status.Placed_updated_at = current_time
            elif status == 'Collected':
                tracking_status.status = 'Collected'
                tracking_status.Collected_updated_at = current_time
            elif status == 'Shipped':
                tracking_status.status = 'Shipped'
                tracking_status.Shipped_updated_at = current_time
            elif status == 'Delivered':
                tracking_status.status = 'Delivered'
                tracking_status.Delivered_updated_at = current_time
            elif status == 'Returned':
                tracking_status.status = 'Returned'
                tracking_status.Returned_updated_at = current_time

            
            tracking_status.save()

            return "Shipment updates retrieved successfully."
        except Exception as e:
            return f"Error retrieving shipment updates: {str(e)}"




User = get_user_model()


class ShippingRegistrationNotification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    username = models.CharField(max_length=150, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    message = models.TextField()

    def __str__(self):
        return f"{self.username} - {self.timestamp}"

    def save(self, *args, **kwargs):
        if not self.username:
            self.username = self.user.username
        super().save(*args, **kwargs)




class TrackingStatus(models.Model):
    product = models.ForeignKey(ShippingRegistration, on_delete=models.CASCADE, null=False)
    Status_Choices = [
        ('Placed', 'Placed'),
        ('Collected', 'Collected'),
        ('Shipped', 'Shipped'),
        ('Delivered', 'Delivered'),
        ('Returned', 'Returned'),
        
    ]

    status = models.CharField(max_length=20, choices=Status_Choices)
    Placed_updated_at = models.DateTimeField(blank=True, null=True)
    Collected_updated_at = models.DateTimeField(blank=True, null=True)
    Shipped_updated_at = models.DateTimeField(blank=True, null=True)
    Delivered_updated_at = models.DateTimeField(blank=True, null=True)
    Returned_updated_at = models.DateTimeField(blank=True, null=True)


    def save(self, *args, **kwargs):
        if not self.pk:
            # This is a new instance
            try:
                # Try to get an existing TrackingStatus associated with the ShippingRegistration
                existing_tracking_status = TrackingStatus.objects.get(product=self.product)
            except TrackingStatus.DoesNotExist:
                # If no existing TrackingStatus exists, set the default status to 'Placed'
                self.status = 'Placed'
                self.Placed_updated_at = datetime.now()
            else:
                # If an existing TrackingStatus exists, update the status_updated_at field based on the new status
                current_time = datetime.now()
                if self.status == 'Placed':
                    existing_tracking_status.Placed_updated_at = current_time
                elif self.status == 'Collected':
                    existing_tracking_status.Collected_updated_at = current_time
                elif self.status == 'Shipped':
                    existing_tracking_status.Shipped_updated_at = current_time
                elif self.status == 'Delivered':
                    existing_tracking_status.Delivered_updated_at = current_time
                elif self.status == 'Returned':
                    existing_tracking_status.Returned_updated_at = current_time
                existing_tracking_status.save()
        else:
            # This is an existing instance
            if self.status != self._state.adding and self.status != self.__class__.objects.get(pk=self.pk).status:
                # If status is being updated and is different from the previous status
                current_time = datetime.now()
                if self.status == 'Placed':
                    self.Placed_updated_at = current_time
                elif self.status == 'Collected':
                    self.Collected_updated_at = current_time
                elif self.status == 'Shipped':
                    self.Shipped_updated_at = current_time
                elif self.status == 'Delivered':
                    self.Delivered_updated_at = current_time
                elif self.status == 'Returned':
                    self.Returned_updated_at = current_time
        super().save(*args, **kwargs)





   
    
