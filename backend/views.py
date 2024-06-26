# views.py
import random
from datetime import datetime, timedelta
from django.utils import timezone
import jwt
import requests
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from dj_rest_auth.serializers import PasswordResetSerializer
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.http import JsonResponse
from rest_framework import status, generics
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.exceptions import NotFound
from rest_framework.generics import RetrieveUpdateAPIView, ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from django.db.models import Q


from .models import CustomUser, ShippingRegistration, Contactus, ShippingRegistrationNotification, \
    TrackingStatus
from .serializers import (UserSerializer, UserViewSerializer, UserProfileUpdateSerializer, ContactusSerializer,
                          ShippingRegSerializer, ShippingRegUpdateSerializer, UserProfileSerializer,
                          AddUserAdminSerializer, NotificationSerializer, ShippingRegAdminSerializer,
                          TrackingStatusSerializer, UpdateTrackingStatusSerializer, ChangePasswordSerializer,
                          PassOTPVerificationSerializer,BillingSerializer,InvoiceNumberSerializer,TrackingStatusUpdateSerializer,DTDCAuthenticationSerializer,ShippingReg1Serializer)
from .tasks import update_tracking_data
from .utils import generate_unique_tracking_id,generate_unique_invoice_number
from django.db import models


class SignUpView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user_id = user.id  # Get the ID of the newly created user
            response_data = {
                "message": "User registered successfully",
                "status": True,
                "user_id": user_id  # Add user ID to the response
            }
            return Response(response_data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']

        user = CustomUser.objects.filter(email=email).first()

        if user is None:
            raise AuthenticationFailed('User not found!', 400)

        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password!', 400)

        payload = {
            'id': user.id,
            'exp': datetime.utcnow() + timedelta(minutes=60),
            'iat': datetime.utcnow()
        }

        token = jwt.encode(payload, 'secret', algorithm='HS256')

        response = Response()

        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {
            'id': user.id,
            'token': token,
            'message': 'Login successful',
            'status': True
        }
        return response


class LoginAdminView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']

        user = CustomUser.objects.filter(is_superuser=True, email=email).first()

        if user is None:
            raise AuthenticationFailed('User not found!', 400)

        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password!', 400)

        payload = {
            'id': user.id,
            'exp': datetime.utcnow() + timedelta(minutes=60),
            'iat': datetime.utcnow()
        }

        token = jwt.encode(payload, 'secret', algorithm='HS256')

        response = Response()

        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {
            'id': user.id,
            'token': token,
            'message': 'Login successful',
            'status': True
        }
        return response


class UserView(APIView):
    def get(self, request, user_id):
        user = CustomUser.objects.filter(id=user_id).first()

        if not user:
            raise NotFound('User not found!')

        serializer = UserViewSerializer(user)
        return Response({
            'user_data': serializer.data,
            'message': 'User Profile View',
            'status': True
        })


class UserProfileView(APIView):
    def get(self, request):
        user = CustomUser.objects.all()
        user = UserProfileSerializer(user, many=True)
        return Response(user.data)


class UserProfileGetView(ListAPIView):
    serializer_class = UserProfileSerializer

    def get_queryset(self):
        single_user = self.kwargs['id']
        return CustomUser.objects.filter(id=single_user)


class UserProfileEditView(RetrieveUpdateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserProfileUpdateSerializer

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response({
            'message': 'Profile updated successfully',
            'status': True,
            'user_data': serializer.data
        })

    def get_object(self):
        queryset = self.filter_queryset(self.get_queryset())
        obj = queryset.filter(id=self.kwargs.get('pk')).first()
        if not obj:
            raise NotFound('User not found!')
        return obj


class UserDeleteView(APIView):
    def delete(self, request, pk):
        try:
            instance = CustomUser.objects.get(pk=pk)
            instance.delete()
            return Response({"message": "User deleted successfully."},
                            status=status.HTTP_204_NO_CONTENT)
        except CustomUser.DoesNotExist:
            return Response({"message": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message': 'Logout successful',
            'status': True
        }
        return response


class ContactUsView(APIView):
    def post(self, request):
        serializer = ContactusSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({
            'message': 'success',
            'status': True,
            'user_data': serializer.data
        }
        )


class ContactUsGetView(APIView):
    def get(self, request):
        contact = Contactus.objects.all()
        Contact = ContactusSerializer(contact, many=True)
        return Response(Contact.data)


class ContactUsDeleteView(APIView):
    def delete(self, request, pk):
        try:
            instance = Contactus.objects.get(pk=pk)
            instance.delete()
            return Response({"message": "Message deleted successfully."},
                            status=status.HTTP_204_NO_CONTENT)
        except Contactus.DoesNotExist:
            return Response({"message": "Message not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

from django.db import transaction


class ShippingRegView(APIView):
    def post(self, request):
        serializer = ShippingRegSerializer(data=request.data, many=isinstance(request.data, list))
        if serializer.is_valid():
            invoice_number = generate_unique_invoice_number()

            with transaction.atomic():
                shipping_reg_instances = []

                for shipping_data in serializer.validated_data:
                    if isinstance(shipping_data, dict):  
                        
                        tracking_id = generate_unique_tracking_id()
                        shipping_data['tracking_id'] = tracking_id

                        
                        pin_code = shipping_data.get('Pin_Code')
                        city = self.fetch_city(pin_code)  
                        if city:
                            shipping_data['City'] = city

                        
                        shipping_data['invoice_number'] = invoice_number
                    else:
                        
                        print(f"Invalid shipping data: {shipping_data}")

                
                if isinstance(serializer.validated_data, list):
                    shipping_reg_instances = serializer.save()
                else:
                    shipping_reg_instances = [serializer.save()]  

               
                for shipping_reg_instance in shipping_reg_instances:
                    TrackingStatus.objects.create(product=shipping_reg_instance, status='Placed',
                                                  Placed_updated_at=datetime.now())

           
            for consignment_data in serializer.data:
                if isinstance(consignment_data, dict):  
                    consignment_data['invoice_number'] = invoice_number
                    consignment_data['tracking_id'] = tracking_id
                else:
                   
                    print(f"Invalid consignment data: {consignment_data}")

            return Response({
                'message': 'Shipping registered successfully.',
                'status': True,
                'invoice_number': invoice_number,
                'consignment_data': serializer.data
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def fetch_city(self, pin_code):
        api_url = f"http://postalpincode.in/api/pincode/{pin_code}"
        try:
            response = requests.get(api_url)
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict) and 'PostOffice' in data:
                    city = data['PostOffice'][0].get('District')
                    return city
        except requests.exceptions.RequestException as e:
            print(f"Error fetching city for pin code {pin_code}: {e}")
        return None




class ShippingReggetView(ListAPIView):
    serializer_class = ShippingRegUpdateSerializer

    def get_queryset(self):
        user = self.kwargs['user_id']
        return ShippingRegistration.objects.filter(user_id=user)
    




class ShippinggetView(ListAPIView):
    serializer_class = ShippingRegSerializer

    def get_queryset(self):
        regid = self.kwargs['id']
        return ShippingRegistration.objects.filter(id=regid)


class Shipping_get_View(ListAPIView):
    serializer_class = ShippingRegSerializer

    def get_queryset(self):
        return ShippingRegistration.objects.all()


class UserDetailsShippingRegistrationAPIView(APIView):
    def get(self, request, user_id, registration_id):
        try:
            user = CustomUser.objects.get(id=user_id)
            shipping_registration = ShippingRegistration.objects.get(user=user, id=registration_id)

            user_serializer = UserProfileSerializer(user)
            shipping_registration_serializer = ShippingReg1Serializer(shipping_registration)

            response_data = {
                "user": user_serializer.data,
                "shipping_registration": shipping_registration_serializer.data
            }

            return Response(response_data, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        except ShippingRegistration.DoesNotExist:
            return Response({"error": "Shipping registration not found"}, status=status.HTTP_404_NOT_FOUND)


class ShippingRegEditView(RetrieveUpdateAPIView):
    queryset = ShippingRegistration.objects.all()
    serializer_class = ShippingRegUpdateSerializer

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        third_party_tracking_id = request.data.get('third_party_tracking_id')
        if third_party_tracking_id:
            instance.third_party_tracking_id = third_party_tracking_id
            instance.save()

        return Response({
            'message': 'Shipping Registration Data Updated Successfully',
            'status': True,
            'user_data': serializer.data
        })

    def get_object(self):
        queryset = self.filter_queryset(self.get_queryset())
        obj = queryset.filter(id=self.kwargs.get('pk')).first()
        if not obj:
            raise NotFound('Shipping registration not found!')
        return obj


class ShippingRegistrationDeleteView(APIView):
    def delete(self, request, pk):
        try:
            instance = ShippingRegistration.objects.get(pk=pk)
            instance.delete()
            return Response({"message": "Shipping registration deleted successfully."},
                            status=status.HTTP_204_NO_CONTENT)
        except ShippingRegistration.DoesNotExist:
            return Response({"message": "Shipping registration not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class adduserview(APIView):
    def post(self, request):
        serializer = AddUserAdminSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({
            'message': 'success',
            'status': True,
            'user_data': serializer.data
        }
        )


class Shipping_Registration_Notification(APIView):
    def post(self, request):
        message = "New shipping registration created."
        notification = ShippingRegistrationNotification.objects.create(message=message)
        serializer = NotificationSerializer(notification)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def get(self, request):
        notification = ShippingRegistrationNotification.objects.all()
        notification = NotificationSerializer(notification, many=True)
        return Response(notification.data)

    def delete(self, request, pk):
        try:
            notification = ShippingRegistrationNotification.objects.get(pk=pk)
            notification.delete()
            return Response({"message": "Notification deleted", "status": True}, status=status.HTTP_204_NO_CONTENT)
        except ShippingRegistrationNotification.DoesNotExist:
            return Response({"message": "Notification not found", "status": False}, status=status.HTTP_404_NOT_FOUND)


class ShippingRegViewAdmin(APIView):
    def post(self, request):
        serializer = ShippingRegAdminSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                'message': 'Shipping registered successfully.',
                'status': True,
                'consignment_data': serializer.data
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ShipmentUpdatesView(APIView):
    def get(self, request, shipment_id):
        try:
            shipment = ShippingRegistration.objects.get(id=shipment_id)
        except ShippingRegistration.DoesNotExist:
            return Response({'error': 'Shipment not found'}, status=status.HTTP_404_NOT_FOUND)

        # Trigger Celery task to fetch updates asynchronously
        update_tracking_data.delay(shipment_id)

        # Return a response indicating that updates will be fetched asynchronously
        return Response({'message': 'Fetching updates for shipment asynchronously.', 'shipment_id': shipment_id},
                        status=status.HTTP_202_ACCEPTED)


class UpdateTrackingIDView(APIView):
    def post(self, request, shipment_id):
        try:
            shipment = ShippingRegistration.objects.get(id=shipment_id)
        except ShippingRegistration.DoesNotExist:
            return Response({'error': 'Shipment not found'}, status=status.HTTP_404_NOT_FOUND)

        # Extract the custom tracking ID from the request data
        custom_tracking_id = request.data.get('custom_tracking_id')

        # Update the shipment record with the custom tracking ID
        shipment.custom_tracking_id = custom_tracking_id
        shipment.save()

        return Response({'message': 'Tracking ID updated successfully'}, status=status.HTTP_200_OK)


def update_tracking(request, tracking_id):
    update_tracking_data.delay(tracking_id)
    return JsonResponse({'message': 'Tracking data update initiated successfully'})


class TrackingDetailsView(APIView):
    def get(self, request, tracking_id):
        try:
            # Search for the TrackingStatus instance associated with the given tracking_id
            tracking_status = TrackingStatus.objects.get(product__tracking_id=tracking_id)

            # Retrieve additional details from ShippingRegistration
            shipping_registration = tracking_status.product

            # Serialize the data
            tracking_status_serializer = TrackingStatusSerializer(tracking_status)
            shipping_registration_serializer = ShippingRegSerializer(shipping_registration)

            return Response({
                'tracking_status': tracking_status_serializer.data,
                'shipping_registration': shipping_registration_serializer.data
            }, status=status.HTTP_200_OK)
        except TrackingStatus.DoesNotExist:
            return Response({'message': 'Tracking ID not found'}, status=status.HTTP_404_NOT_FOUND)


class UpdateTrackingStatusView(APIView):
    def put(self, request, tracking_id):
        try:
            # Retrieve the TrackingStatus instance associated with the given tracking_id
            tracking_status = TrackingStatus.objects.get(product__tracking_id=tracking_id)
        except TrackingStatus.DoesNotExist:
            return Response({'message': 'Tracking ID not found'}, status=status.HTTP_404_NOT_FOUND)

        # Update the tracking status based on the request data
        serializer = UpdateTrackingStatusSerializer(tracking_status, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'status': True, 'data': serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AcceptRejectShippingRegistration(APIView):
    def post(self, request, registration_id):
        try:
            registration = ShippingRegistration.objects.get(id=registration_id)
        except ShippingRegistration.DoesNotExist:
            return Response({'message': 'Shipping registration not found'}, status=status.HTTP_404_NOT_FOUND)

        action = request.data.get('action')  # Assuming the action is provided in the request data

        if action == 'accept':
            registration.registration_status = 'ACCEPTED'
            registration.save()
            return Response({'message': 'Shipping registration accepted','registration_status': registration.registration_status,
                             'Tracking id': registration.tracking_id}, status=status.HTTP_200_OK)
        elif action == 'reject':
            registration.registration_status = 'REJECTED'
            registration.save()
            return Response({'message': 'Shipping registration rejected','registration_status': registration.registration_status,
                             'Tracking id': registration.tracking_id}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)
        
        
class FetchLocationAPIView(APIView):
    def get(self, request):
        pin_code = request.query_params.get('pin_code')
        if pin_code:
            locations = self.fetch_location(pin_code)
            return Response(locations)
        else:
            return Response({'error': 'Pin code not provided'}, status=400)

    def fetch_location(self, pin_code):
        api_url = f"http://postalpincode.in/api/pincode/{pin_code}"
        try:
            response = requests.get(api_url)
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict) and 'PostOffice' in data and data['PostOffice']:
                    post_offices = []
                    for post_office in data['PostOffice']:
                        post_office_name = post_office.get('Name')
                        city = post_office.get('District')
                        district = post_office.get('District')
                        state = post_office.get('State')
                        post_offices.append({
                            'post_office_name': post_office_name,
                            'city': city,
                            'district': district,
                            'state': state
                        })
                    return post_offices
        except requests.exceptions.RequestException as e:
            print(f"Error fetching location for pin code {pin_code}: {e}")
        return []



#password_reset
User = get_user_model()
class PasswordResetView(generics.GenericAPIView):
    serializer_class = PasswordResetSerializer
    def post(self, request):
        email = request.data.get('email', None)
        user = User.objects.filter(email=email).first()
        if user:
            otp = ''.join([str(random.randint(0, 9)) for _ in range(4)])
            user.otp_secret_key = otp
            user.save()
            email_subject = 'Password Reset OTP'
            email_body = f'Your OTP for password reset is: {otp}'
            to_email = [user.email]
            send_mail(email_subject, email_body, from_email=None, recipient_list=to_email)
            return Response({'detail': 'OTP sent successfully.','status':True}, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'User not found.','status':False}, status=status.HTTP_404_NOT_FOUND)
        

        
User = get_user_model()
class PassOTPVerificationView(generics.GenericAPIView):
    serializer_class = PassOTPVerificationSerializer
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get('email', None)
        otp = serializer.validated_data.get('otp', None)
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'detail': f'User with email {email} not found.', 'status': False}, status=status.HTTP_404_NOT_FOUND)
        if not self.verify_otp(user.otp_secret_key, otp):
            return Response({'detail': 'Invalid OTP.', 'status': False}, status=status.HTTP_400_BAD_REQUEST)
        user.otp_secret_key = None
        user.save()
        return Response({'detail': 'OTP verification successful. Proceed to reset password.', 'status': True}, status=status.HTTP_200_OK)
    def verify_otp(self, secret_key, otp):
        return secret_key == otp
    

class ChangePasswordView(generics.GenericAPIView):
    serializer_class = ChangePasswordSerializer
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get('email')
        new_password = serializer.validated_data.get('new_password')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'detail': f'User with email {email} not found.', 'status': False}, status=status.HTTP_404_NOT_FOUND)
        user.set_password(new_password)
        user.save()
        return Response({'detail': 'Password changed successfully.', 'status': True}, status=status.HTTP_200_OK)





class CleanShippingRegistrationsAPIView(APIView):
    def post(self, request, format=None):
        two_months_ago = timezone.now() - timezone.timedelta(days=60)
        old_shippings = ShippingRegistration.objects.filter(Booking_date__lte=two_months_ago)
        deleted_count, _ = old_shippings.delete()
        return Response({"message": f"Deleted {deleted_count} old shipping registrations."})

    





class BillingView(APIView):
    def get(self, request, user_id, invoice_number):
        try:
            # Retrieve orders for the specified user and invoice number
            orders = ShippingRegistration.objects.filter(user_id=user_id, invoice_number=invoice_number)
            # Serialize the orders
            serializer = BillingSerializer(orders, many=True)
            # Get the unique invoice number
            unique_invoice_number = orders.first().invoice_number if orders.exists() else None
            # Return the response with orders and invoice number
            return Response({
                'message': 'Datas By Invoice Retrieved successfully.',
                'status': True,
                'invoice_number': unique_invoice_number,
                'orders': serializer.data
            }, status=status.HTTP_201_CREATED)
        
           
        
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserInvoiceNumbersView(APIView):
    def get(self, request, user_id):
        try:
            # Retrieve unique invoice numbers for the specified user
            unique_invoice_numbers = ShippingRegistration.objects.filter(user_id=user_id).values_list('invoice_number', flat=True).distinct()
            
            # Initialize a dictionary to store booking dates for each invoice number
            booking_dates_dict = {}
            for invoice_number in unique_invoice_numbers:
                booking_dates = ShippingRegistration.objects.filter(user_id=user_id, invoice_number=invoice_number).values_list('Booking_date', flat=True)
                booking_dates_dict[invoice_number] = list(booking_dates)
            
            # Serialize the unique invoice numbers and booking dates
            serializer = InvoiceNumberSerializer({'invoice_numbers': unique_invoice_numbers, 'booking_dates': booking_dates_dict})
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class TrackingStatusUpdateView(APIView):
    def post(self, request, format=None):
        serializer = TrackingStatusUpdateSerializer(data=request.data)
        if serializer.is_valid():
            tracking_ids = serializer.validated_data['tracking_ids']
            status_value = serializer.validated_data['status']
            try:
                # Update tracking status for each provided tracking ID
                for tracking_id in tracking_ids:
                    # Search for ShippingRegistration by either third_party_tracking_id or tracking_id
                    shipping_registration = ShippingRegistration.objects.filter(
                        models.Q(third_party_tracking_id=tracking_id) | models.Q(tracking_id=tracking_id)
                    ).first()
                    if shipping_registration:
                        # Update or create TrackingStatus instance
                        tracking_status, _ = TrackingStatus.objects.get_or_create(product=shipping_registration)
                        setattr(tracking_status, f"{status_value.lower()}_updated_at", timezone.now())
                        tracking_status.status = status_value
                        tracking_status.save()
                    else:
                        return Response({"message": f"No shipping registration found with tracking ID '{tracking_id}'."},
                                        status=status.HTTP_404_NOT_FOUND)
                return Response({"message": "Tracking statuses updated successfully."}, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DTDCAuthenticationView(APIView):
    def post(self, request, format=None):
        serializer = DTDCAuthenticationSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data.get('username')
            password = serializer.validated_data.get('password')
            third_party_tracking_id = serializer.validated_data.get('third_party_tracking_id')
            
            # Define the authentication endpoint URL
            authentication_url = "http://ctbsplusapi.dtdc.com/dtdc-staging-api/api/dtdc/authenticate"
            
            # Prepare request parameters
            params = {"username": username, "password": password}
            if third_party_tracking_id:
                params['third_party_tracking_id'] = third_party_tracking_id
            
            # Make the request to the authentication endpoint
            response = requests.get(authentication_url, params=params)

            # Check if the request was successful
            if response.status_code == 200:
                # Extract the authentication token from the response
                token = response.json().get("token")
                return Response({"token": token}, status=200)
            else:
                return Response({"error": "Failed to authenticate"}, status=response.status_code)
        else:
            return Response(serializer.errors, status=400)


class ShippingRegistrationBulkDeleteView(APIView):
    def post(self, request):
        try:
            
            registration_ids = request.data.get('registration_ids', [])
            if not registration_ids:
                return Response({"message": "No registration IDs provided for deletion."},
                                status=status.HTTP_400_BAD_REQUEST)

           
            registrations_to_delete = ShippingRegistration.objects.filter(Q(pk__in=registration_ids))
            if not registrations_to_delete:
                return Response({"message": "No matching registrations found for deletion."},
                                status=status.HTTP_404_NOT_FOUND)

           
            registrations_to_delete.delete()

            return Response({"message": "Shipping registrations deleted successfully."},
                            status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class ShippingRegistrationAllSearchView(APIView):
    def get(self, request):
        try:
            start_date_str = request.query_params.get('start_date')
            end_date_str = request.query_params.get('end_date')

            if not start_date_str or not end_date_str:
                return Response({"message": "Both start_date and end_date are required as query parameters in dd/mm/yyyy format."},
                                status=status.HTTP_400_BAD_REQUEST)

            start_date = datetime.strptime(start_date_str, '%d/%m/%Y').date()
            end_date = datetime.strptime(end_date_str, '%d/%m/%Y').date()

            # Query orders between start_date and end_date
            orders = ShippingRegistration.objects.filter(Booking_date__range=[start_date, end_date])

            
            serializer = ShippingRegSerializer(orders, many=True)

            return Response({"orders": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ShippingRegistrationSearchView(APIView):
    def get(self, request, user_id):
        try:
            start_date_str = request.query_params.get('start_date')
            end_date_str = request.query_params.get('end_date')

            if not start_date_str or not end_date_str:
                return Response({"message": "start_date and end_date are required as query parameters in dd/mm/yyyy format."},
                                status=status.HTTP_400_BAD_REQUEST)

            start_date = datetime.strptime(start_date_str, '%d/%m/%Y').date()
            end_date = datetime.strptime(end_date_str, '%d/%m/%Y').date()

            
            orders = ShippingRegistration.objects.filter(user_id=user_id, Booking_date__range=[start_date, end_date])

           
            serializer = ShippingRegSerializer(orders, many=True)

            return Response({"orders": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        



class ShippingRegistrationFilterView(APIView):
    def get(self, request):
        try:
            filter_type = request.query_params.get('filter_type')
            if not filter_type:
                return Response({"message": "filter_type parameter is required."}, status=400)
            
            today = timezone.now().date()

            if filter_type == 'today':
                start_date = today
                end_date = today
            elif filter_type == 'yesterday':
                start_date = today - timedelta(days=1)
                end_date = today - timedelta(days=1)
            elif filter_type == 'last_7_days':
                start_date = today - timedelta(days=6)
                end_date = today
            elif filter_type == 'last_30_days':
                start_date = today - timedelta(days=29)
                end_date = today
            elif filter_type == 'last_month':
                first_day_of_this_month = today.replace(day=1)
                first_day_of_last_month = first_day_of_this_month - timedelta(days=1)
                start_date = first_day_of_last_month.replace(day=1)
                end_date = first_day_of_this_month - timedelta(days=1)
            elif filter_type == 'this_month':
                start_date = today.replace(day=1)
                end_date = today
            elif filter_type == 'custom':
                start_date_str = request.query_params.get('start_date')
                end_date_str = request.query_params.get('end_date')
                if not start_date_str or not end_date_str:
                    return Response({"message": "Both start_date and end_date are required for custom filter."}, status=400)
                start_date = datetime.strptime(start_date_str, '%d/%m/%Y').date()
                end_date = datetime.strptime(end_date_str, '%d/%m/%Y').date()
            else:
                return Response({"message": "Invalid filter_type parameter."}, status=400)

            
            shipping_registrations = ShippingRegistration.objects.filter(Booking_date__range=[start_date, end_date])

           
            serializer = ShippingRegSerializer(shipping_registrations, many=True)

            return Response({"shipping_registrations": serializer.data}, status=200)
        except Exception as e:
            return Response({"message": str(e)}, status=500)
        

class BulkAcceptRejectShippingRegistration(APIView):
    def post(self, request):
        registrations_ids = request.data.get('registration_ids', [])
        action = request.data.get('action')

        if not registrations_ids or not action:
            return Response({'message': 'Registration IDs and action are required.'}, status=status.HTTP_400_BAD_REQUEST)

        if action not in ['accept', 'reject']:
            return Response({'message': 'Invalid action.'}, status=status.HTTP_400_BAD_REQUEST)

        registrations = ShippingRegistration.objects.filter(id__in=registrations_ids)

        if not registrations.exists():
            return Response({'message': 'No shipping registrations found for the provided IDs.'}, status=status.HTTP_404_NOT_FOUND)

        if action == 'accept':
            registrations.update(registration_status='ACCEPTED')
        elif action == 'reject':
            registrations.update(registration_status='REJECTED')

        updated_registrations = registrations.values('id', 'registration_status', 'tracking_id')
        return Response({'message': 'Bulk update successful.', 'registrations': list(updated_registrations)}, status=status.HTTP_200_OK)
    

class BulkShippingRegEditView(APIView):
    def post(self, request):
        registration_ids = request.data.get('registration_ids', [])
        update_data = request.data.get('update_data', {})

        if not registration_ids or not update_data:
            return Response({'message': 'Registration IDs and update data are required.'}, status=status.HTTP_400_BAD_REQUEST)

        # Validate update data using the serializer
        serializer = ShippingRegUpdateSerializer(data=update_data, partial=True)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        errors = []
        success_updates = []

        for registration_id in registration_ids:
            try:
                registration = ShippingRegistration.objects.get(id=registration_id)
                for key, value in update_data.items():
                    setattr(registration, key, value)
                registration.save()
                success_updates.append({
                    'id': registration.id,
                    'updated_fields': update_data,
                })
            except ShippingRegistration.DoesNotExist:
                errors.append({'id': registration_id, 'error': 'Shipping registration not found'})
            except Exception as e:
                errors.append({'id': registration_id, 'error': str(e)})

        return Response({
            'message': 'Bulk update process completed',
            'status': True,
            'success_updates': success_updates,
            'errors': errors
        }, status=status.HTTP_200_OK if not errors else status.HTTP_207_MULTI_STATUS)