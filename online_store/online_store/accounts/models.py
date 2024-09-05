from faker import Faker
import logging

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import ValidationError

from django.conf import settings
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.core.exceptions import ObjectDoesNotExist
from django.db import models
from django.urls import reverse
from django.utils.timezone import now
from django.utils.translation import gettext_lazy as _

from online_store.general.utils import random_string_alphadigit

logger = logging.getLogger(__name__)

PASSWORD_HELP_TEXT = _("""Leave the field blank if you do not need to change the user’s password.
              The password must contain more than 7 characters and must not contain only numbers.""")


# class CustomUserQuerySet(models.QuerySet):
#     def suppliers(self):
#         return self.filter(role__in=[self.Roles.GUIDE, self.Roles.LANDLORD, self.Roles.TRANSFER_PROVIDER])


class CustomUserManager(BaseUserManager):
    """
    Custom user model manager where email is the unique identifier
    for authentication instead of username.
    """

    def create_user(self, email, password, **extra_fields):
        """
        Create and save a User with the given email and password.
        """
        if not email:
            raise ValueError('Email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, **extra_fields):
        """
        Create and save a SuperUser with the given email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if not extra_fields.get('is_staff'):
            raise ValueError('Superuser must have is_staff=True.')
        if not extra_fields.get('is_superuser'):
            raise ValueError('Superuser must have is_superuser=True.')
        return self.create_user(email, password, **extra_fields)

    def get_queryset(self):
        return CustomUserQuerySet(self.model, using=self._db)

    def suppliers(self):
        return self.get_queryset().visible()


class User(AbstractBaseUser, PermissionsMixin):

    class Roles(models.TextChoices):
        # admin service
        ADMIN = ("admin", "Admin")
        # client service
        CLIENT = ("client", "Client")
        # guide service
        MANAGER = ("manager", "Manager")

    created_at = models.DateTimeField(_("created at"), auto_now_add=True)
    updated_at = models.DateTimeField(_("updated at"), auto_now=True)
    self_deletion = models.DateTimeField(
        _("self deletion"), null=True, blank=True)
    is_staff = models.BooleanField(
        _("staff status"), default=False,
        help_text=_("Designates whether the user can log into this admin site."))
    is_active = models.BooleanField(
        _("active"), default=True,
        help_text=_("Designates whether this user should be treated as active. "
                    "Unselect this instead of deleting accounts."))

    email = models.EmailField(max_length=254)
    role = models.CharField(
        _("role"), max_length=30, choices=Roles.choices, db_index=True)

    objects = CustomUserManager()

    EMAIL_FIELD = "email"
    USERNAME_FIELD = "id"
    REQUIRED_FIELDS = ["email"]

    class Meta:
        verbose_name = _("User")
        verbose_name_plural = _("Users")
        swappable = 'AUTH_USER_MODEL'
        constraints = [
            models.UniqueConstraint(
                fields=['email', 'role'],
                name='email_role_unique'
            ),
        ]

    def __str__(self):
        return f'{self.role}-{self.email}'

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

    def clean(self):
        super().clean()
        self.email = self.__class__.objects.normalize_email(self.email)

    @classmethod
    def get_roles_list(cls):
        return list(cls.Roles.__members__.values())

    def get_full_name(self):
        """Return the first_name plus the last_name, with a space in between."""
        full_name = self.email
        if self.profile:
            full_name = f"{self.profile.first_name} {self.profile.last_name}"
        return full_name.strip()

    def create_token(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }

    @property
    def profile(self):
        """Returns profile according to user role"""
        try:
            if self.role == self.Roles.ADMIN:
                return self.adminprofile
            elif self.role == self.Roles.CLIENT:
                return self.clientprofile
            elif self.role == self.Roles.MANAGER:
                return self.managerprofile

        except ObjectDoesNotExist:
            return None

    def is_admin(self):
        return self.is_superuser or (self.is_staff and self.role == 'admin')

    @property
    def is_client(self):
        return self.role == self.Roles.CLIENT

    @property
    def is_manager(self):
        return self.role == self.Roles.MANAGER

    @staticmethod
    def is_email_used(email, user_role, raise_exception=True):
        """
        Validates email among users with given role
        :raise_exception - if True, raise exception, else return boolean
        """

        if User.objects.filter(email__iexact=email, role=user_role).exists():
            if raise_exception:
                raise ValidationError(_("This email is already used"))
            else:
                return True
        else:
            return False

    @property
    def profile_name(self):
        """Returns name of profile class, lower case"""
        role_str = self.role.replace('_', '')
        return f'{role_str}profile'

    @property
    def profile_url(self):
        """Returns link to the user profile"""
        if self.profile and USER_ROLE_TO_PROFILE.get(self.role):
            app = 'online_store.accounts'
            url = reverse(
                f'admin:{app}_{self.profile_name}_change',
                args=[self.profile.id])
            return url

    def create_profile(self):
        """Creates profile according to user role"""
        if self.profile is None:
            match self.role:
                case self.Roles.ADMIN:
                    AdminProfile.create_user_profile(self)
                case self.Roles.CLIENT:
                    ClientProfile.create_user_profile(self)
                case self.Roles.MANAGER:
                    ManagerProfile.create_user_profile(self)


class BaseProfile(models.Model):
    """Contains common profile information for all roles"""

    class Sex(models.TextChoices):
        MALE = ("M", _("Male"))
        FEMALE = ("F", _("Female"))

    user = models.OneToOneField(User, on_delete=models.CASCADE, verbose_name=_("user"))
    first_name = models.CharField(
        _("first_name"), max_length=150, null=True, blank=True)
    last_name = models.CharField(
        _("last_name"), max_length=150, null=True, blank=True)
    phone = models.CharField(
        _("phone"), max_length=15, null=True, blank=True, default='')

    class Meta:
        abstract = True

    def __str__(self):
        return self.user.__str__()

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    def base_clean_profile(self):
        """
        clear profile fields
        """
        from general.test_utils import random_alphadigital

        self.first_name = 'removed'
        self.last_name = 'removed'
        self.phone = 'removed'
        self.save()

        self.user.is_active = False
        fake = Faker()
        Faker.seed(0)
        email = f'removed.{random_string_alphadigit(4)}.{fake.email()}'
        cnt = 0
        while User.objects.filter(
                email=email, role=self.user.role).exists() and cnt < 100:
            email = f'removed.{random_string_alphadigit(4)}.{fake.email()}'
            cnt += 1
        self.user.email = email
        self.user.self_deletion = now()
        self.user.save()


class ExtendedProfile(BaseProfile):

    class Statuses(models.TextChoices):
        APPROVED = ("approved", _("Approved"))      # admin approved profile
        CANCELLED = ("cancelled", _("Cancelled"))   # admin denied profile moderation

    about = models.TextField(_("about"), blank=True, null=True)
    status = models.CharField(
        _("status"), choices=Statuses.choices,
        max_length=30, default=Statuses.PENDING, db_index=True)

    class Meta:
        abstract = True

    @property
    def is_approved(self):
        return self.status == self.Statuses.APPROVED

    def base_clean_profile(self):
        """
        clear profile fields
        """
        from general.test_utils import random_alphadigital

        self.about = None
        self.status = ExtendedProfile.Statuses.CANCELLED
        self.first_name = 'removed'
        self.last_name = 'removed'
        self.phone = 'removed'
        self.save()

        self.user.is_active = False
        fake = Faker()
        Faker.seed(0)
        email = f'removed.{random_string_alphadigit(4)}.{fake.email()}'
        cnt = 0
        while User.objects.filter(
                email=email, role=self.user.role).exists() and cnt < 1000:
            email = f'removed.{random_string_alphadigit(4)}.{fake.email()}'
            cnt += 1
        self.user.email = email
        self.user.self_deletion = now()
        self.user.save()


class AdminProfile(BaseProfile):
    class Meta:
        verbose_name = _("Admin")
        verbose_name_plural = _("Admins")

    @classmethod
    def create_user_profile(cls, user):
        """
        create new class item for the user
        """
        pass


class ClientProfile(BaseProfile):
    has_reserved_funds = models.BooleanField(
        "has reserved funds", default=False)

    class Meta:
        verbose_name = _("Client")
        verbose_name_plural = _("Clients")

    def clean_profile(self):
        """
        clear client profile fields
        """
        self.base_clean_profile()

    def deactivate_related_objects(self):
        """
        deactivate objects related to this guide user
        """
        pass

    @classmethod
    def create_user_profile(cls, user):
        """
        create new class item for the user
        """
        if not cls.objects.filter(user=user):
            cls.objects.create(
                user=user,
                sex='M',
            )


class ManagerProfile(ExtendedProfile):
    class Meta:
        verbose_name = _("Manager Profile")
        verbose_name_plural = _("Manager Profiles")

    def clean_profile(self):
        """
        clear guide profile fields
        """
        self.service_type = None
        self.guide_service_type = None
        self.save()

        self.base_clean_profile()

    def deactivate_related_objects(self):
        """
        deactivate objects related to this guide user
        """
        pass

    @classmethod
    def create_user_profile(cls, user):
        """
        create new class item for the user
        """
        if not cls.objects.filter(user=user):
            cls.objects.create(
                user=user,
                sex='M',
                status=ExtendedProfile.Statuses.APPROVED
            )


USER_ROLE_TO_PROFILE = {
    User.Roles.ADMIN: None,
    User.Roles.CLIENT: ClientProfile,
    User.Roles.MANAGER: ManagerProfile,
}
