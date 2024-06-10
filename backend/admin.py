from django.contrib import admin

# Register your models here.

from backend.models import CustomUser,Contactus,ShippingRegistration

admin.site.register(CustomUser),
admin.site.register(Contactus),
admin.site.register(ShippingRegistration),
