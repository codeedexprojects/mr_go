from django.urls import path

from backend import views
from backend.views import Shipping_Registration_Notification


urlpatterns = [
    
#signup/signin/login/logout

    path('signup/', views.SignUpView.as_view(), name='signup'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('LoginAdmin/', views.LoginAdminView.as_view(), name='LoginAdminView'),
    path('logout/', views.LogoutView.as_view(), name='logout'),

#adminlogin

    

#userprofile

    path('userprofile/<int:user_id>/', views.UserView.as_view(), name='user_profile'),
    path('UserProfileView/', views.UserProfileView.as_view(), name='UserProfileView'),
    path('UserProfileGetView/<int:id>/', views.UserProfileGetView.as_view(), name='UserProfileGetView'),
    path('userprofileedit/<int:pk>/', views.UserProfileEditView.as_view(), name='user_profile_edit_by_id'),
    path('UserDeleteView/<int:pk>/', views.UserDeleteView.as_view(), name='user_profile_delete_by_id'),




    

    #contactus

    path('ContactUsView/', views.ContactUsView.as_view(), name='ContactUsView'),
    path('ContactUsGetView/', views.ContactUsGetView.as_view(), name='ContactUsGetView'),
    path('ContactUsDeleteView/<int:pk>/', views.ContactUsDeleteView.as_view(), name='ContactUsDeleteView'),



#shipping Registration

    path('ShippingRegView/', views.ShippingRegView.as_view(), name='ShippingRegView'),
    path('ShippingReggetView/<int:user_id>/', views.ShippingReggetView.as_view(), name='ShippingReggetView'),
    path('ShippinggetView/<int:id>/', views.ShippinggetView.as_view(), name='ShippinggetView'),
    path('Shipping_get_View/', views.Shipping_get_View.as_view(), name='Shipping_get_View'),

    #shipping reg edit

    path('ShippingRegEditView/<int:pk>/', views.ShippingRegEditView.as_view(), name='ShippingRegEditView'),

    #shipping reg bulk edit

    path('bulk-edit-registration/', views.BulkShippingRegEditView.as_view(), name='bulk-edit-registration'),


    #shipping reg delete

    path('shipping-registrations/<int:pk>/', views.ShippingRegistrationDeleteView.as_view(),
         name='shipping-registration-delete'),


     #shipping bulk delete    

    path('shipping-registrations/bulk-delete/', views.ShippingRegistrationBulkDeleteView.as_view(),
     name='shipping-registration-bulk-delete'),


    path('user-details-shipping-registration/<int:user_id>/<int:registration_id>/',
         views.UserDetailsShippingRegistrationAPIView.as_view(), name='user-details-shipping-registration'),



#     path('billingview/', views.billingview.as_view(), name='billingview'),
#     path('billingGetview/<int:user_id>/<int:product_id>/', views.billingGetview.as_view(), name='billingGetview'),



    path('adduserview/', views.adduserview.as_view(), name='adduserview'),



    path('ShippingRegViewAdmin/', views.ShippingRegViewAdmin.as_view(), name='ShippingRegViewAdmin'),


#shipping Notification

    path('shipping-registration/notification/', views.Shipping_Registration_Notification.as_view(),
         name='shipping-registration-notification'),
    path('shipping-notifications/<int:pk>/', Shipping_Registration_Notification.as_view(),
         name='shipping_notification_detail'),


    path('shipment-updates/<int:shipment_id>/', views.ShipmentUpdatesView.as_view(), name='shipment_updates'),


#tracking status    

    path('update-tracking/<int:shipment_id>/', views.UpdateTrackingIDView.as_view(), name='update_tracking'),

    
    path('update-tracking/<str:tracking_id>/', views.update_tracking, name='update_tracking'),



    path('tracking-details/<str:tracking_id>/', views.TrackingDetailsView.as_view(), name='tracking-details'),
    path('update-tracking-status/<str:tracking_id>/', views.UpdateTrackingStatusView.as_view(),
         name='update-tracking-status'),

#shippin reg accept reject

    path('shipping-registration/<int:registration_id>/accept-reject/', views.AcceptRejectShippingRegistration.as_view(),
         name='accept-reject-shipping-registration'),


    path('fetch_location/', views.FetchLocationAPIView.as_view(), name='fetch_location'),

    #bulk accept reject 
    path('bulk-accept-reject-registration/', views.BulkAcceptRejectShippingRegistration.as_view(), name='bulk-accept-reject-registration'),



   #password
    path('password-reset/', views.PasswordResetView.as_view(), name='password-reset'),
    path('password-otp/', views.PassOTPVerificationView.as_view(), name='otp-verification'),
    path('change-password/', views.ChangePasswordView.as_view(), name='change-password'),
    path('clean-shipping-registrations/', views.CleanShippingRegistrationsAPIView.as_view(), name='clean-shipping-registrations'),

#     path('admin-check/', views.AdminPermissionCheck.as_view(), name='admin-check'),
    path('billing/<int:user_id>/<str:invoice_number>/', views.BillingView.as_view(), name='billing-list'),
    path('invoicenumbers/<int:user_id>/', views.UserInvoiceNumbersView.as_view(), name='user-invoice-numbers'),

    #tracking status
    path('update-tracking-status/', views.TrackingStatusUpdateView.as_view(), name='update_tracking_status'),
    path('dtdc/<str:third_party_tracking_id>/', views.DTDCAuthenticationView.as_view(), name='dtdc-status'),

    #shipping reg bulk delete
    path('shipping-registrations/bulk-delete/', views.ShippingRegistrationBulkDeleteView.as_view(),name='shipping-registration-bulk-delete'),
    


    #shipping reg single cus search
    path('shipping-registrations/search/<int:user_id>/', views.ShippingRegistrationSearchView.as_view(),name='shipping-registration-search'),

    #shipping reg all filter by date
    path('shipping-registrations/search/', views.ShippingRegistrationAllSearchView.as_view(),name='shipping-registration-search-all'),

    #filter by days,mnths
    path('shipping-registrations/filter/', views.ShippingRegistrationFilterView.as_view(), name='shipping-registration-filter'),



]
