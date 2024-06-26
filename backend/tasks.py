from celery import shared_task
from datetime import timedelta
from .models import ShippingRegistration
from .third_party_tracking_api import update_tracking_data

@shared_task
def update_tracking_data(tracking_id):
    shipment = ShippingRegistration.objects.get(tracking_id=tracking_id)
    tracking_updates = update_tracking_data(tracking_id)
    shipment.status = tracking_updates.get('status', 'Unknown')
    shipment.save()
