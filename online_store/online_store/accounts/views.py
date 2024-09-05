import json
import jwt
#from jwt.algorithms import RSAAlgorithm
# from logging import getLogger
# from pprint import pprint
# import requests
# from time import time
#
# from django.conf import settings
# from django.utils.translation import gettext as _
#
# from rest_framework.decorators import api_view
# from rest_framework.exceptions import ValidationError
# from rest_framework.generics import RetrieveUpdateAPIView, CreateAPIView, ListAPIView
# from rest_framework.parsers import JSONParser, MultiPartParser
# from rest_framework.permissions import AllowAny, IsAuthenticated
# from rest_framework.request import Request
# from rest_framework.response import Response
#
# from rest_framework.views import APIView
# from rest_framework import status
#
# from config.constants.error_messages import PASSWORDS_DO_NOT_MATCH
# from config.permissions import IsGuideUser, IsClientUser, IsGuideOrClientUser
# from config.utils import get_frontend_url
# from orders.models import Order
# from services.emailer import EmailService
# from services.emailer.templates import SIGNUP_SUCCESS, SIGNUP_FOR_AUTOMATED_CLIENTS
# from services.google_oauth import GoogleOAuth
# from services.photos import PhotoService
# from services.stripe_service import StripeService
#
# from general.utils import language_native_name
# from .models import (
#     User, VerificationCode, ClientProfile, GuideProfile, LandlordProfile,
#     PartnerProfile, TransferProviderProfile, GoogleAuthAttempt,
#     USER_ROLE_TO_PROFILE, AgentClient
# )
# from .serializers import *
# from .utils import automated_signup_send_letter, signup_send_email
#
# logger = getLogger(__name__)


class GetRolesView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        roles = [
            {
                'role': role_id,
                'visible_name': role_name,
            }
            for role_id, role_name in User.Roles.choices
        ]
        return Response(roles)


# class SignUpSendCodeView(CreateAPIView):
#     """Send email with verification code"""
#
#     serializer_class = SignUpInitialSerializer
#     permission_classes = [AllowAny]
#
#     def post(self, request, *args, **kwargs):
#         serializer = self.get_serializer(data=request.data)
#         if serializer.is_valid(raise_exception=True):
#             verification_code = serializer.save()
#
#             # send verification email
#             email_sent = self.send_signup_verification_code(
#                 verification_code.email, verification_code.code)
#             logger.info(f'Sent email::{email_sent}')
#             if email_sent:
#                 return Response("Success")
#             else:
#                 verification_code.delete()
#                 return Response({'detail': _("Email was not sent, try again please")},
#                                 status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#
#     def send_signup_verification_code(self, email, code):
#         """Send email with signup verification code"""
#         logger.info(f'Sent email::send_signup_verification_code')
#         subject = "Sign Up Verification"
#
#         language = self.request.headers.get("Accept-Language", "en")
#         if language == "ru":
#             subject = "Подтверджение регистрации"
#
#         user_ip = self.request.headers.get("X-Forwarded-For", "Unknown")
#
#         email_context = {
#             "language": language,
#             "location": user_ip,
#             "verification_code": code,
#             "domain_guide": settings.DOMAIN_GUIDE,
#             "domain_client": settings.DOMAIN_CLIENT,
#         }
#         logger.info(f'Sent email::send_data = {email_context}')
#         return EmailService().send_email_with_verification_code(
#             email=email, subject=subject, mode="signup", context=email_context
#         )
#
#
# class SignUpVerifyCodeView(APIView):
#     permission_classes = [AllowAny]
#
#     def post(self, request):
#         serializer = SignUpVerifyCodeSerializer(data=request.data)
#         if serializer.is_valid(raise_exception=True):
#             return Response()
#
#
# class SignUpView(CreateAPIView):
#     permission_classes = [AllowAny]
#
#     def post(self, request, *args, **kwargs):
#         data = request.data
#
#         # check if we need to generate a password for user
#         if automated := request.query_params.get('automated'):
#             random_password = User.objects.make_random_password(length=10)
#             data['password'] = random_password
#             data['confirm_password'] = random_password
#
#         serializer = self.get_serializer(data=data)
#         if serializer.is_valid():
#             user = serializer.save()
#
#             # TODO: move the code above to celery task
#
#             # create Stripe customer
#             StripeService.create_customer(user)
#
#             # if user is one of suppliers, send email
#             if automated:
#                 automated_signup_send_letter(
#                     user, data.get('password'),
#                     language=request.headers.get("Accept-Language", 'ru'))
#             else:
#                 self.send_signup_email(
#                     user,
#                     language=request.headers.get("Accept-Language", 'ru'))
#
#             return Response(serializer.data, status=status.HTTP_201_CREATED)
#         else:
#             raise ValidationError(serializer.errors)
#
#     def get_serializer_class(self):
#         roles_mappings = {
#             User.Roles.CLIENT: SignUpClientSerializer,
#             User.Roles.GUIDE: SignUpGuideSerializer,
#             User.Roles.PARTNER: SignUpPartnerSerializer,
#             User.Roles.LANDLORD: SignUpLandlordSerializer,
#             User.Roles.TRANSFER_PROVIDER: SignUpTransferProviderSerializer,
#         }
#         return roles_mappings[self.request.data['role']]
#
#     def get_serializer_context(self):
#         roles_mappings = {
#             User.Roles.CLIENT: {'source': 'clientprofile', 'model': ClientProfile},
#             User.Roles.GUIDE: {'source': 'guideprofile', 'model': GuideProfile},
#             User.Roles.PARTNER: {'source': 'partnerprofile', 'model': PartnerProfile},
#             User.Roles.LANDLORD: {'source': 'landlordprofile', 'model': LandlordProfile},
#             User.Roles.TRANSFER_PROVIDER: {'source': 'transferproviderprofile', 'model': TransferProviderProfile},
#         }
#         return roles_mappings[self.request.data['role']]
#
#     def send_signup_email(self, user, language='ru'):
#         """Send followup email after signup"""
#         signup_send_email(user, language)
#
#
# class SignUpAsClientView(SignUpView):
#     permission_classes = [AllowAny]
#
#     def post(self, request, *args, **kwargs):
#         request.data['role'] = User.Roles.CLIENT
#         return super().post(request, *args, **kwargs)
#
#
# class SignUpAsPartnerView(SignUpView):
#     permission_classes = [AllowAny]
#
#     def post(self, request, *args, **kwargs):
#         request.data['role'] = User.Roles.PARTNER
#         return super().post(request, *args, **kwargs)
#
#
# class SignUpAsGuideView(SignUpView):
#     permission_classes = [AllowAny]
#
#     def post(self, request, *args, **kwargs):
#         request.data['role'] = User.Roles.GUIDE
#         return super().post(request, *args, **kwargs)
#
#
# class SignUpAsLandlordView(SignUpView):
#     permission_classes = [AllowAny]
#
#     def post(self, request, *args, **kwargs):
#         request.data['role'] = User.Roles.LANDLORD
#         return super().post(request, *args, **kwargs)
#
#
# class SignUpAsTransferProviderView(SignUpView):
#     permission_classes = [AllowAny]
#
#     def post(self, request, *args, **kwargs):
#         request.data['role'] = User.Roles.TRANSFER_PROVIDER
#         return super().post(request, *args, **kwargs)
#
#
# class ProfileView(RetrieveUpdateAPIView):
#     serializer_type_class = {
#         'admin': AdminSerializer,
#         'client': ClientSerializer,
#         'guide': GuideSerializer,
#         'partner': PartnerSerializer,
#         'landlord': LandlordSerializer,
#         'transfer_provider': TransferProviderSerializer
#     }
#
#     def put(self, request, *args, **kwargs):
#         user = request.user
#         srl_class = self.get_profile_serializer(user.role)
#
#         request_data = dict(request.data)
#         # pprint(request_data)
#         language_id = request_data.pop('language') if 'language' in request_data else None
#         languages = request_data.pop('languages') if 'languages' in request_data else ''
#         currency_code = request_data.pop('currency') if 'currency' in request_data else None
#
#         serializer = srl_class(instance=user.profile, data=request_data, partial=True)
#         if serializer.is_valid(raise_exception=True):
#             user_profile = serializer.save()
#             if language_id:
#                 user_profile.set_language(language_id)
#             if currency_code:
#                 user_profile.set_currency(currency_code)
#             if user.role == User.Roles.GUIDE:
#                 if languages:
#                     user.profile.clear_languages()
#                     user.profile.add_languages(languages)
#
#             return Response(self.get_serializer_class()(user).data)
#
#     def get_object(self):
#         return self.request.user
#
#     def get_serializer_class(self):
#         role = self.get_object().role
#         return self.serializer_type_class[role]
#
#     @staticmethod
#     def get_profile_serializer(role):
#         data = {
#             User.Roles.ADMIN: AdminProfileSerializer,
#             User.Roles.CLIENT: ClientProfileSerializer,
#             User.Roles.GUIDE: GuideProfileSerializer,
#             User.Roles.TRANSFER_PROVIDER: TransferProviderProfileSerializer,
#             User.Roles.LANDLORD: LandlordProfileSerializer,
#         }
#         return data[role]
#
#
# class SignInView(APIView):
#     permission_classes = [AllowAny]
#     serializer_type_class = {
#         'admin': AdminSerializer,
#         'client': ClientSerializer,
#         'guide': GuideSerializer,
#         'partner': PartnerSerializer,
#         'landlord': LandlordSerializer,
#         'transfer_provider': TransferProviderSerializer
#     }
#
#     def post(self, request):
#         serializer = SignInSerializer(data=request.data)
#         if serializer.is_valid(raise_exception=True):
#             user = serializer.validated_data['user']
#             serializer = self.get_serializer_class(user.role)
#             return Response({'user': serializer(user).data, 'token': user.create_token()})
#
#     def get_serializer_class(self, role):
#         return self.serializer_type_class[role]
#
#
# class GoogleAuthView(APIView):
#     permission_classes = [AllowAny]
#
#     def put(self, request, *args, **kwargs):
#         """Google Auth - Generate auth url"""
#         logger.info(f"GoogleAuthView::PUT::request data = {request.data}")
#         serializer = GoogleAuthPutSrl(data=request.data)
#         if serializer.is_valid(raise_exception=True):
#             with transaction.atomic():
#                 google_auth_attempt = GoogleAuthAttempt.objects.create(
#                     role=serializer.validated_data['role'],
#                     request_from_url=serializer.validated_data['request_from_url']
#                 )
#                 data = GoogleOAuth().gen_auth_url(
#                     redirect_url=serializer.validated_data['redirect_url'],
#                     unique_id=str(google_auth_attempt.id),
#                     role=google_auth_attempt.role
#                 )
#             logger.info(f"GoogleAuthView::PUT::response data = {data}")
#             return Response(data=data)
#
#     def post(self, request, *args, **kwargs):
#         """Google Auth - Authenticate user"""
#
#         logger.info(f"GoogleAuthView::post::request data = {request.data}")
#         google_access_token = request.data.get('access_token', None)
#         if not google_access_token:
#             return Response(_("Invalid auth token"), status=status.HTTP_400_BAD_REQUEST)
#
#         state = request.data.get('state', None)
#         if not state:
#             return Response(_("Invalid state"), status=status.HTTP_400_BAD_REQUEST)
#
#         auth_attempt_id, role = state.split("_")
#         logger.info(f"GoogleAuthView::post::{auth_attempt_id = }, {role = }")
#
#         try:
#             auth_attempt = GoogleAuthAttempt.objects.get(id=auth_attempt_id)
#         except GoogleAuthAttempt.DoesNotExist:
#             logger.error("GoogleAuthView::post::GoogleAuthAttempt not found")
#             return Response(_("Something went wrong"), status=status.HTTP_400_BAD_REQUEST)
#
#         if role != auth_attempt.role:
#             return Response(_("Invalid role"), status=status.HTTP_400_BAD_REQUEST)
#
#         user_info_from_google = GoogleOAuth().check_token(google_access_token)
#         if not user_info_from_google:
#             return Response(_("Invalid auth token"), status=status.HTTP_400_BAD_REQUEST)
#
#         profile = None
#         # update user with google id if user exists; otherwise create user from google data
#         try:
#             user = User.objects.get(email=user_info_from_google.email, role=role)
#             if user.google_id:
#                 if user.google_id != user_info_from_google.id:
#                     return Response(status=status.HTTP_403_FORBIDDEN)
#             else:
#                 user.google_id = user_info_from_google.id
#                 user.save()
#
#             profile = user.profile
#         except User.DoesNotExist:
#             with transaction.atomic():
#                 # create user from data from Google
#                 random_password = User.objects.make_random_password(length=10)
#                 user = User.objects.create_user(
#                     email=user_info_from_google.email,
#                     password=random_password,
#                     role=role,
#                     google_id=user_info_from_google.id,
#                 )
#                 profile_class = USER_ROLE_TO_PROFILE[role]
#                 if profile_class:
#                     profile = profile_class.objects.create(
#                         user=user,
#                         first_name=user_info_from_google.given_name,
#                         last_name=user_info_from_google.family_name
#                     )
#                     logger.debug(
#                         f"Google Auth::post :: {profile_class.__name__} was created for user {user.email}")
#
#                 automated_signup_send_letter(
#                     user, random_password,
#                     language=request.headers.get("Accept-Language", 'ru'))
#
#         if profile and not profile.photo:
#             logger.info(f"Google Auth::post :: {user_info_from_google.picture = }")
#             user_photo = GoogleOAuth().get_user_image(user_info_from_google.picture)
#             profile.photo = user_photo
#             profile.save()
#
#         srl_class = self.get_profile_serializer(user.role)
#         data = {
#             'user': srl_class(user).data,
#             'token': user.create_token(),
#             "request_from_url": auth_attempt.request_from_url
#         }
#         logger.info(f"GoogleAuthView::post::response data = {data}")
#         return Response(data)
#
#     @staticmethod
#     def get_profile_serializer(role):
#         serializer_type_class = {
#             'admin': AdminSerializer,
#             'client': ClientSerializer,
#             'guide': GuideSerializer,
#             'landlord': LandlordSerializer,
#             'transfer_provider': TransferProviderSerializer
#         }
#         return serializer_type_class[role]
#
#
# class AppleAuthView(APIView):
#     """View to auth user by Apple"""
#     permission_classes = [AllowAny]
#
#     def fetch_apple_public_key(self, kid):
#         """получение нужного публичного ключа с сайта apple"""
#         key_json = None
#         key_payload = requests.get(settings.APPLE_PUBLIC_KEY_URL).json()
#         for _key in key_payload['keys']:
#             if _key['kid'] == kid:
#                 key_json = _key
#                 break
#
#         return RSAAlgorithm.from_jwk(key_json)
#
#     def decode_token(self, user_token, audience):
#         """декодирование токена"""
#         token_header = jwt.get_unverified_header(user_token)
#         kid = token_header['kid']
#         algorithm = token_header['alg']
#         public_key = self.fetch_apple_public_key(kid)
#
#         try:
#             token = jwt.decode(
#                 user_token,
#                 public_key,
#                 audience=audience,
#                 algorithms=[algorithm])
#         except jwt.exceptions.ExpiredSignatureError as e:
#             raise Exception("That token has expired")
#         except jwt.exceptions.InvalidAudienceError as e:
#             raise Exception("That token's audience did not match")
#         except Exception as e:
#             print(e)
#             raise Exception("An unexpected error occoured")
#
#         return token
#
#     def post(self, request, *args, **kwargs):
#         """Apple Auth - Authenticate user"""
#         serializer = AppleAuthSerializer(data=request.data)
#
#         if serializer.is_valid(raise_exception=True):
#             data = serializer.validated_data
#             logger.info(f"AppleAuthView::post::request data = {request.data}")
#             apple_identity_token = data.get('identity_token', None)
#             if not apple_identity_token:
#                 return Response(
#                     _("Invalid identity token"),
#                     status=status.HTTP_400_BAD_REQUEST)
#
#             audience = settings.APPLE_GUIDE_APP_ID
#             if data['role'] == 'client':
#                 audience = settings.APPLE_CLIENT_APP_ID
#             info = self.decode_token(apple_identity_token, audience)
#
#             token_serializer = TokenInfoSerializer(data=info)
#             if token_serializer.is_valid(raise_exception=True):
#                 data_info = token_serializer.validated_data
#
#                 email = None
#                 role = data['role']
#
#                 if data_info['aud'] != audience:
#                     return Response(
#                         _("Invalid identity token audience."),
#                         status=status.HTTP_400_BAD_REQUEST)
#
#                 # if not data_info['email'] or data_info['email_verified'] != 'true':
#                     # return Response(
#                     # _("Identity token. No email or email is not verified."),
#                     # status=status.HTTP_400_BAD_REQUEST)
#                 # else:
#                     # email = data_info['email']
#
#                 email = data_info.get('email')
#
#                 if time() > data_info['exp']:
#                     return Response(
#                         _("Identity token is expired."),
#                         status=status.HTTP_400_BAD_REQUEST)
#
#                 if data_info['iss'] != 'https://appleid.apple.com':
#                     return Response(
#                         _("Wrong identity token iss."),
#                         status=status.HTTP_400_BAD_REQUEST)
#
#                 if not data_info['sub'] and data_info['sub'] != data['user']:
#                     return Response(
#                         _("Identity token sub does not equal user apple id."),
#                         status=status.HTTP_400_BAD_REQUEST)
#                 else:
#                     user_apple_id = data_info['sub']
#
#                 profile = None
#                 # update user with apple id if user exists; otherwise create user from apple data
#                 try:
#                     if email:
#                         # get user by email
#                         user = User.objects.get(email=email, role=role)
#                         if user.apple_id:
#                             if user.apple_id != user_apple_id:
#                                 return Response(
#                                     _("Token user ID does not equal user apple_id."),
#                                     status=status.HTTP_403_FORBIDDEN)
#                         else:
#                             user.apple_id = user_apple_id
#                             user.save()
#                     else:
#                         # get user by apple_id
#                         user = User.objects.get(apple_id=data['user'], role=role)
#
#                     profile = user.profile
#                 except User.DoesNotExist:
#                     if not email:
#                         return Response(
#                             _("Unable to register a user without email."),
#                             status=status.HTTP_400_BAD_REQUEST)
#
#                     with transaction.atomic():
#                         # create user from data from Apple
#                         user = User.objects.create(
#                             email=email,
#                             role=role,
#                             apple_id=user_apple_id,
#                         )
#                         profile_class = USER_ROLE_TO_PROFILE[role]
#                         if profile_class:
#                             profile = profile_class.objects.create(
#                                 user=user,
#                                 first_name=data.get('given_name', ''),
#                                 last_name=data.get('family_name', ''),
#                             )
#                             logger.debug(
#                                 f"Apple Auth::post :: {profile_class.__name__} was created for user {user.email}")
#
#         srl_class = GoogleAuthView.get_profile_serializer(user.role)
#         return Response({
#             'user': srl_class(user).data,
#             'token': user.create_token(),
#         })
#
#
# class ChangeEmailView(APIView):
#     permission_classes = [IsAuthenticated]
#     serializer_type_class = {
#         'admin': AdminSerializer,
#         'client': ClientSerializer,
#         'guide': GuideSerializer,
#         'landlord': LandlordSerializer,
#         'transfer_provider': TransferProviderSerializer
#     }
#
#     def get_serializer_class(self, role):
#         return self.serializer_type_class[role]
#
#     def post(self, request):
#         """Accept new email and send verification code via email"""
#         user = request.user
#         serializer = RequestChangeEmailSerializer(data=request.data, context={'role': user.role})
#
#         if serializer.is_valid(raise_exception=True):
#             # Create and send verification code to new email
#             new_email = serializer.validated_data['email']
#             vc = VerificationCode.objects.create(
#                 email=new_email,
#                 role=user.role,
#                 context=VerificationCode.Types.CHANGE_EMAIL
#             )
#
#             email_sent = self.send_code_to_change_email(user, new_email, vc.code)
#             if email_sent:
#                 return Response("Success")
#             else:
#                 return Response({'detail': _("Email was not sent, try again please")},
#                                 status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#
#     def send_code_to_change_email(self, user, new_email, code):
#         """Send email with signup verification code"""
#
#         subject = "Confirm Email"
#
#         language = self.request.headers.get("Accept-Language", "en")
#         if language == "ru":
#             subject = "Подтверждение Email"
#
#         user_ip = self.request.headers.get("X-Forwarded-For", "Unknown")
#
#         email_context = {
#             "language": language,
#             "location": user_ip,
#             "verification_code": code,
#             "user_name": user.get_full_name(),
#             "domain_guide": settings.DOMAIN_GUIDE,
#             "domain_client": settings.DOMAIN_CLIENT,
#         }
#         return EmailService().send_email_with_verification_code(
#             email=new_email, subject=subject, mode="signup", context=email_context
#         )
#
#     def put(self, request):
#         """Check verification code and change email if its valid"""
#         user = request.user
#         serializer = ChangeEmailSerializer(data=request.data, context={'role': user.role})
#         if serializer.is_valid(raise_exception=True):
#             new_email = serializer.validated_data['email']
#             user.email = new_email
#             user.save()
#             serializer = self.get_serializer_class(user.role)
#             return Response({'user': serializer(user).data, 'token': user.create_token()})
#
#
# class ValidateEmailView(APIView):
#     permission_classes = [AllowAny]
#
#     def post(self, request):
#         """Validate email: check if client with email already exists"""
#         if email := request.data.get('email'):
#             result = User.is_email_used(email, User.Roles.CLIENT, raise_exception=False)
#             return Response(result)
#         else:
#             return Response(_("email is required"))
#
#
# class CheckPasswordView(APIView):
#     """
#     API method to check if user password is correct. Used in change password flow.
#     """
#
#     def post(self, request):
#         user = request.user
#         password = request.data.get('password')
#         if not user.check_password(password):
#             raise ValidationError({"password": _("Password is not correct")})
#         else:
#             return Response()
#
#
# class ChangePasswordView(APIView):
#     serializer_class = ChangePasswordSerializer
#
#     def put(self, request):
#         user = request.user
#         serializer = ChangePasswordSerializer(data=request.data)
#
#         if serializer.is_valid(raise_exception=True):
#             # Check old password
#             data = serializer.data
#             if not user.check_password(data.get("password")):
#                 raise ValidationError({"password": _("Current password is not correct")})
#             # Check if new password is equal to old password
#             if data.get("new_password") == data.get("old_password"):
#                 raise ValidationError(
#                     {"password": _("New password should not be equal to old password")})
#             # set_password also hashes the password that the user will get
#             elif data.get("confirm_password") != data.get("new_password"):
#                 raise ValidationError({"password": PASSWORDS_DO_NOT_MATCH})
#
#             user.set_password(data.get("new_password"))
#             user.save()
#             return Response({
#                 'message': _("Your password has been changed"),
#                 'token': user.create_token()
#             })
#
#
# class ForgotPasswordView(APIView):
#     permission_classes = [AllowAny]
#     serializer_class = ForgotPasswordSerializer
#
#     def post(self, request):
#         serializer = ForgotPasswordSerializer(data=request.data)
#         if serializer.is_valid(raise_exception=True):
#             vc = VerificationCode.objects.create(
#                 email=serializer.validated_data['email'],
#                 role=serializer.validated_data['role'],
#                 context=VerificationCode.Types.RESET_PWD
#             )
#             user = User.objects.get(
#                 email=serializer.validated_data['email'], role=serializer.validated_data['role'])
#
#             email_sent = self.send_code_to_reset_password(user=user, code=vc.code)
#             if email_sent:
#                 return Response("Success")
#             else:
#                 return Response({'detail': _("Email was not sent, try again please")},
#                                 status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#
#     def send_code_to_reset_password(self, user, code):
#         """Send email with verification code to reset password"""
#
#         subject = "Password Recovery"
#
#         language = self.request.headers.get("Accept-Language", "en")
#         if language == "ru":
#             subject = "Восстановление пароля"
#
#         user_ip = self.request.headers.get("X-Forwarded-For", "Unknown")
#
#         email_context = {
#             "language": language,
#             'location': user_ip,
#             'verification_code': code,
#             'user_name': user.get_full_name(),
#             "domain_guide": settings.DOMAIN_GUIDE,
#             "domain_client": settings.DOMAIN_CLIENT,
#         }
#         return EmailService().send_email_with_verification_code(
#             email=user.email, subject=subject, mode="reset_password", context=email_context
#         )
#
#
# class ResetPasswordView(APIView):
#     permission_classes = [AllowAny]
#     serializer_class = ResetPasswordSerializer
#
#     def post(self, request):
#         serializer = ResetPasswordVerifyCodeSerializer(data=request.data)
#         if serializer.is_valid(raise_exception=True):
#             return Response("Success")
#
#     def put(self, request):
#         serializer = ResetPasswordSerializer(data=request.data)
#         if serializer.is_valid(raise_exception=True):
#             user = User.objects.get(
#                 email=serializer.validated_data['email'],
#                 role=serializer.validated_data['role']
#             )
#             user.set_password(serializer.validated_data['password'])
#             user.save()
#
#             return Response({
#                 'message': _("Your password has been changed"),
#                 'token': user.create_token()
#             })
#
#
# class UpdateProfilePhotoView(RetrieveUpdateAPIView):
#     """Updates profile photo"""
#     permission_classes = [IsAuthenticated]
#     parser_classes = [MultiPartParser]
#     serializer_class = ProfilePhotoSerializer
#
#     def get_object(self):
#         return self.request.user.profile
#
#
# class GetGuideTypesView(ListAPIView):
#     """ GET list of guide service types """
#
#     permission_classes = [IsAuthenticated]
#     serializer_class = GuideServiceTypeSerializer
#     queryset = GuideServiceType.objects.all()
#
#
# class SetGuideTypeView(APIView):
#     """ PUT service type for the guide """
#
#     permission_classes = [IsGuideUser]
#     serializer_class = ServiceTypeSerializer
#
#     def put(self, request: Request, *args, **kwargs) -> Response:
#         user = request.user
#         if not user.is_guide:
#             return Response(_("Access denied"), status=status.HTTP_403_FORBIDDEN)
#
#         serializer = ServiceTypeSerializer(data=request.data)
#         if serializer.is_valid(raise_exception=True):
#             with transaction.atomic():
#                 profile = user.profile
#                 service_type = GuideServiceType.objects.get(
#                     id=serializer.data.get('service_type'))
#                 profile.guide_service_type = service_type
#                 profile.save()
#
#                 out_serializer = GuideProfileSerializer(profile)
#
#             return Response(out_serializer.data)
#
#
# class RemoveProfileView(APIView):
#     permission_classes = [IsGuideOrClientUser]
#
#     def post(self, request):
#         """
#         the user makes request to remove self account
#         """
#         user = request.user
#         profile = user.profile
#
#         with transaction.atomic():
#             profile.clean_profile()
#             profile.deactivate_related_objects()
#
#             # установить статус 'administration' для всех заказов
#             # которые новые или оплачены
#             # и заказаны этим клиентом или это заказы для экскурсий этого гида
#             if user.role == User.Roles.GUIDE:
#                 orders = Order.objects.filter(service__owner=user)
#             if user.role == User.Roles.CLIENT:
#                 orders = Order.objects.filter(owner=user)
#
#             orders = orders.filter(
#                 status__in=(Order.Statuses.NEW, Order.Statuses.PAID))
#
#             orders.update(status=Order.Statuses.ADMINISTRATION)
#
#         return Response({'user': user.id, 'removed': True})
#
#
# @api_view(['PUT'])
# def set_profile_language(request):
#     """
#     set profile language
#     """
#     user = request.user
#     profile = user.profile
#
#     try:
#         language = Language.objects.get(pk=request.data.get('language'))
#     except ValueError:
#         try:
#             language = Language.objects.get(iso=request.data.get('language'))
#         except ValueError:
#             return Response(
#                 _('Language matching query does not exist.'),
#                 status=status.HTTP_404_NOT_FOUND)
#
#     profile.language = language
#     profile.save()
#
#     data = LanguageSerializer(profile.language).data
#     native_name = language_native_name(data['iso'])
#     if native_name:
#         data['name'] = native_name
#     return Response({'language': data}, status=status.HTTP_200_OK)
#
#
# class JoinAgentView(APIView):
#     permission_classes = [IsClientUser]
#
#     def post(self, request):
#         """
#         the user makes request to join to agent with this referral code
#         """
#         user = request.user
#
#         # убрать записи без агента, если такие есть
#         AgentClient.objects.filter(agent__isnull=True).delete()
#         # проверить, прикреплён ли клиент к любому агенту
#         agent_client = AgentClient.objects.filter(client=user).first()
#         if agent_client is not None:
#             agent = agent_client.agent
#             if agent.profile:
#                 agent_profile = agent.profile
#                 return Response({
#                     'joining': 'current',
#                     'active': agent_profile.is_active_agent,
#                     'agent': agent_profile.full_name,
#                     'ref_code': agent_profile.ref_code})
#             else:
#                 agent_client.delete()
#
#         try:
#             agent_profile = PartnerProfile.objects.get(
#                 ref_code=request.data.get('ref_code'), agent=True)
#             agent = agent_profile.user
#         except Order.DoesNotExist:
#             return Response(
#                 _("Agent with this referral code is not found"),
#                 status=status.HTTP_404_NOT_FOUND)
#
#         with transaction.atomic():
#             agent_client = AgentClient.objects.create(
#                 client=user, agent=agent)
#
#             return Response({
#                 'joining': 'new',
#                 'active': agent_profile.is_active_agent,
#                 'agent': agent_profile.full_name,
#                 'ref_code': agent_profile.ref_code})
