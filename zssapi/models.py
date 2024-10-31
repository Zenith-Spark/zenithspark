import uuid
from django.db import models
from django.conf import settings
from django.utils import timezone
from .managers import CustomUserManager
from django_userforeignkey.models.fields import UserForeignKey
from django.contrib.auth.models import AbstractBaseUser,PermissionsMixin, BaseUserManager, Group, Permission




GENDER = [
    ('MALE', 'male'),
    ('FEMALE', 'female'),
    ]
class CustomUserManager(BaseUserManager):
    def create_user(self, email_address, password=None, **extra_fields):
        if not email_address:
            raise ValueError("The Email Address field must be set")
        
        email_address = self.normalize_email(email_address)
        user = self.model(email_address=email_address, **extra_fields)
        if password:
            user.set_password(password)  # This ensures the password is hashed
        else:
            raise ValueError("The Password field must be set")
        user.save(using=self._db)
        return user

    def create_superuser(self, email_address, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get('is_superuser') is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email_address, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    full_name = models.CharField(max_length=255)
    email_address = models.EmailField(max_length=255, unique=True)
    gender = models.CharField(max_length=13, choices=GENDER, default='FEMALE')
    plain_password = models.CharField(max_length=128, blank=True, null=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    referral_code = models.CharField(max_length=10, unique=True, blank=True, null=True)
    referred_by = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='referrals')
    date_joined = models.DateTimeField(default=timezone.now)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    groups = models.ManyToManyField(Group, related_name='custom_user_set', blank=True)
    user_permissions = models.ManyToManyField(Permission, related_name='custom_user_set', blank=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email_address'
    EMAIL_FIELD = 'email_address'
    REQUIRED_FIELDS = ['full_name']

    def __str__(self):
        return self.email_address

    def has_perm(self, perm, obj=None):
        return self.is_superuser

    def has_module_perms(self, app_label):
        return self.is_superuser
    
    def save(self, *args, **kwargs):
        # Generate a unique referral code only if it is not already set
        if not self.referral_code:
            self.referral_code = str(uuid.uuid4())[:8]  # Generate a unique referral code
        if self.plain_password:  
            self.set_password(self.plain_password)
        super().save(*args, **kwargs)


class Network(models.Model):
    name = models.CharField(max_length=50, unique=True)
    symbol = models.CharField(max_length=10)
    wallet_address = models.CharField(max_length=255)
    balance = models.DecimalField(max_digits=18, decimal_places=8, default=0, null=True)

    def __str__(self):
        return self.name


class InvestmentPlan(models.Model):
    name = models.CharField(max_length=100)
    profit_percentage = models.DecimalField(max_digits=5, decimal_places=2)  # e.g., 18.00
    duration_days = models.IntegerField()  # e.g., 3
    minimum_amount = models.DecimalField(max_digits=10, decimal_places=2)
    maximum_amount = models.DecimalField(max_digits=10, decimal_places=2)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.name} - {self.profit_percentage}% in {self.duration_days} days"


class Investment(models.Model):

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('active', 'Active'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='investments')
    investment_plan = models.ForeignKey(InvestmentPlan, on_delete=models.PROTECT)
    network = models.ForeignKey(Network, on_delete=models.CASCADE, null=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    expected_profit = models.DecimalField(max_digits=10, decimal_places=2)
    investment_time = models.DateTimeField(default=timezone.now)
    return_time = models.DateTimeField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    def __str__(self):
        return f"{self.user.email_address}'s {self.investment_plan} investment of {self.amount}"

    class Meta:
        ordering = ['-investment_time']


class Notification(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='notifications')
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Notification for {self.user.email_address}: {self.message[:50]}..."


class Deposit(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    transaction_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, blank=True)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    network = models.ForeignKey(Network, on_delete=models.CASCADE)
    amount_usd = models.DecimalField(max_digits=10, decimal_places=2)
    amount_crypto = models.DecimalField(max_digits=18, decimal_places=8, null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.transaction_id} - {self.user.email_address} - {self.amount_usd} USD"


class Withdrawal(models.Model):

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    transaction_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    network = models.ForeignKey('Network', on_delete=models.CASCADE)  # Assuming you have a Network model
    amount_usd = models.DecimalField(max_digits=10, decimal_places=2)
    amount_crypto = models.DecimalField(max_digits=18, decimal_places=8, null=True, blank=True)
    wallet_address = models.CharField(max_length=255)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.transaction_id} - {self.user.email_address} - {self.amount_usd} USD"


class KYC(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected')
    )
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    document = models.FileField(upload_to='kyc_documents/')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):

        return f"KYC for {self.user.email_address}"