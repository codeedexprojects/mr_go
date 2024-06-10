from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib import messages
from .models import ShippingRegistration, ShippingRegistrationNotification


@receiver(post_save, sender=ShippingRegistration)
def shipping_registration_notification(sender, instance, created, **kwargs):
    if created:
        # Create a notification instance
        ShippingRegistrationNotification.objects.create(
            user=instance.user,
            message=f"Rgistered a new order: {instance}"
        )

