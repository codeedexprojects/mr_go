from django.utils.text import slugify
from rest_framework import serializers

from .models import CustomUser, Contactus, ShippingRegistration, ShippingRegistrationNotification, \
    TrackingStatus


class  UserSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(write_only=True)
    mobile = serializers.CharField(write_only=True, required=True)
    full_name = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ['id', 'full_name', 'email', 'password', 'password2', 'mobile']
        extra_kwargs = {
            'password': {'write_only': True},
            'password2': {'write_only': True},
        }

    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
        if password != password2:
            raise serializers.ValidationError({"Error": "Passwords do not match"})
        return data

    def validate_mobile(self, value):
        if CustomUser.objects.filter(mobile=value).exists():
            raise serializers.ValidationError("Mobile number already exists.")
        return value

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        password2 = validated_data.pop('password2', None)

        email = validated_data.get('email')

        username = slugify(email.split('@')[0])
        count = 1
        while CustomUser.objects.filter(username=username).exists():
            username = f"{slugify(email.split('@')[0])}_{count}"
            count += 1

        instance = self.Meta.model(**validated_data, username=username)

        if password is not None:
            instance.set_password(password)

        instance.save()
        return instance


class UserProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = '__all__'


class UserViewSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = '__all__'


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'mobile', 'full_name', 'username', 'primary_address', 'secondary_address', 'city',
                  'state', 'pincode', 'business_name', 'business_details']


class ContactusSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contactus
        fields = '__all__'


class BillingSerializer(serializers.ModelSerializer):
    tracking_id = serializers.CharField(read_only=True)  # Add a field for tracking ID

    class Meta:
        model = ShippingRegistration
        fields = '__all__'

class ShippingReg1Serializer(serializers.ModelSerializer):
    tracking_id = serializers.CharField(read_only=True)  # Add a field for tracking ID

    class Meta:
        model = ShippingRegistration
        fields = '__all__'

        
class ShippingRegSerializer(serializers.ModelSerializer):
    tracking_id = serializers.CharField(read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)
    Booking_date = serializers.DateField(format='%d/%m/%Y',allow_null=True, required=False)
    Delivery_date = serializers.DateField(format='%d/%m/%Y',allow_null=True, required=False)

    class Meta:
        model = ShippingRegistration
        fields = '__all__'
        

    def create(self, validated_data):
        # Remove 'tracking_id' from validated data if it's present
        tracking_id = validated_data.pop('tracking_id', None)

        instance = super().create(validated_data)

        # If 'tracking_id' was generated, assign it to the instance
        if tracking_id:
            instance.tracking_id = tracking_id
            instance.save()

        return instance

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        for field_name, value in ret.items():
            if isinstance(value, str) and not value.strip():  # Check if value is an empty string
                ret[field_name] = None  # Convert empty string to None
        return ret
   
        

class ShippingRegUpdateSerializer(serializers.ModelSerializer):
    Booking_date = serializers.DateField(format="%d/%m/%Y", input_formats=['%d/%m/%Y', 'iso-8601'])
    Delivery_date = serializers.DateField(format="%d/%m/%Y", input_formats=['%d/%m/%Y', 'iso-8601'])
    

    class Meta:
        model = ShippingRegistration
        fields = '__all__'

        
        def get_Total_price(self, obj):
            return obj.Price_per_kg * obj.Total_weight





    


class AddUserAdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['email', 'mobile', 'full_name', 'username', 'primary_address', 'secondary_address',
                  'city', 'state', 'pincode', 'business_name', 'business_details']


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = ShippingRegistrationNotification
        fields = '__all__'


class ShippingRegAdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = ShippingRegistration
        fields = ['Shipping_Through', 'Name', 'Mobile', 'Pin_Code', 'City', 'Address', 'Content_Type', 'Number_of_box',
                  'Declared_value', 'Consignment', 'user']


class TrackingStatusSerializer(serializers.ModelSerializer):
    
    
    class Meta:
        model = TrackingStatus
        fields = '__all__'


class UpdateTrackingStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = TrackingStatus
        fields = ['status']


class ShippingRegistrationAcceptRejectSerializer(serializers.Serializer):
    action = serializers.ChoiceField(choices=['accept', 'reject'])


class PassOTPVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(min_length=4)

class ChangePasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    new_password = serializers.CharField(write_only=True)
    confirm_new_password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        new_password = data.get('new_password')
        confirm_new_password = data.get('confirm_new_password')
        if new_password != confirm_new_password:
            raise serializers.ValidationError("New password and confirm new password do not match.")
        return data
    


class InvoiceNumberSerializer(serializers.Serializer):
    invoice_numbers = serializers.ListField(child=serializers.CharField())
    booking_dates = serializers.DictField(child=serializers.ListField(child=serializers.DateField()))

    def to_representation(self, instance):
        data = super().to_representation(instance)
        unique_booking_dates = {}
        for invoice_number, booking_dates in data['booking_dates'].items():
            unique_booking_dates[invoice_number] = list(set(booking_dates))
        data['booking_dates'] = unique_booking_dates
        return data


class TrackingStatusUpdateSerializer(serializers.Serializer):
    tracking_ids = serializers.ListField(child=serializers.CharField())
    status = serializers.CharField()

    def validate_status(self, value):
        valid_statuses = ['Placed', 'Collected', 'Shipped', 'Delivered', 'Returned']
        if value not in valid_statuses:
            raise serializers.ValidationError("Invalid status provided.")
        return value

    def validate(self, data):
        if 'tracking_ids' in data:
            for tracking_id in data['tracking_ids']:
                if not ShippingRegistration.objects.filter(tracking_id=tracking_id).exists():
                    raise serializers.ValidationError(f"No shipping registration found with tracking ID '{tracking_id}'.")
        return data

class DTDCAuthenticationSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()
    third_party_tracking_id = serializers.CharField(required=False)



