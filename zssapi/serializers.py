from rest_framework.serializers import ModelSerializer, EmailField, CharField, IntegerField, SerializerMethodField
from .models import CustomUser, Investment, Deposit, Withdrawal, Network, Notification, InvestmentPlan, KYC
from rest_framework.exceptions import ValidationError
from rest_framework import serializers
from django.db.models import Sum



class CustomUserSerializer(ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('id', 'full_name', 'email_address', 'password', 'gender', 
                 'ip_address', 'last_login_ip', 'date_joined', 
                 'referral_code', 'referred_by')
        extra_kwargs = {
            'password': {'write_only': True},
            'referral_code': {'read_only': True},  # Make referral_code read-only
            'date_joined': {'read_only': True},    # Make date_joined read-only
        }
    
    def create(self, validated_data):
        # Remove referral_code from validated_data since it's auto-generated
        validated_data.pop('referral_code', None)
        
        # Use the manager's create_user method to handle password hashing
        user = CustomUser.objects.create_user(
            email_address=validated_data['email_address'],
            password=validated_data['password'],
            full_name=validated_data.get('full_name'),
            ip_address=validated_data.get('ip_address'),
            last_login_ip=validated_data.get('last_login_ip'),
            referred_by=validated_data.get('referred_by'),
        )
        return user

    def update(self, instance, validated_data):
        # Remove referral_code from validated_data to prevent updates
        validated_data.pop('referral_code', None)
        
        # Update the password if provided
        password = validated_data.pop('password', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if password:
            instance.set_password(password)
        instance.save()
        return instance

class NotificationSerializer(ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'message', 'is_read', 'created_at']



class InvestmentPlanSerializer(ModelSerializer):
    class Meta:
        model = InvestmentPlan
        fields = '__all__'

class InvestmentSerializer(ModelSerializer):
    plan_name = CharField(source='investment_plan.name', read_only=True)
    duration_days = IntegerField(source='investment_plan.duration_days', read_only=True)
    investment_plan_name = CharField(write_only=True)
    network_name = CharField(write_only=True)
    network_symbol = CharField(source='network.symbol', read_only=True)
    user_email = EmailField(source='user.email', read_only=True)
    user_full_name = CharField(source='user.full_name', read_only=True)

    class Meta:
        model = Investment
        fields = ['id', 'user', 'user_email', 'user_full_name', 'investment_plan', 'investment_plan_name', 'plan_name',
                 'network_name', 'network_symbol', 'amount', 'expected_profit', 
                 'investment_time', 'return_time', 'status', 'duration_days']
        read_only_fields = ['id', 'user', 'investment_plan', 'expected_profit',
                           'investment_time', 'return_time', 'status']


class NetworkSerializer(ModelSerializer):
    class Meta:
        model = Network
        fields = ['id', 'name', 'symbol', 'wallet_address']

class DepositSerializer(ModelSerializer):
    class Meta:
        model = Deposit
        fields = ['id', 'transaction_id', 'user', 'network', 'amount_usd', 'amount_crypto', 'status', 'created_at', 'updated_at']  # Removed 'date'
        read_only_fields = ['id', 'transaction_id', 'user', 'created_at', 'updated_at', 'status']


class MakeDepositSerializer(ModelSerializer):
    class Meta:
        model = Deposit
        fields = ['network', 'amount_usd', 'amount_crypto']

    def validate_amount_usd(self, value):
        if value <= 0:
            raise serializers.ValidationError("Amount must be greater than zero")
        return value

class UpdateDepositStatusSerializer(ModelSerializer):
    class Meta:
        model = Deposit
        fields = ['status']

class AdminWithdrawalSerializer(ModelSerializer):
    class Meta:
        model = Withdrawal
        fields = ['status']


class WithdrawalSerializer(ModelSerializer):
    created_at = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", input_formats=["%Y-%m-%d %H:%M:%S"])
    updated_at = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", input_formats=["%Y-%m-%d %H:%M:%S"])

    class Meta:
        model = Withdrawal
        fields = ['id', 'transaction_id', 'user', 'network', 'amount_usd', 'amount_crypto', 'wallet_address', 'status', 'created_at', 'updated_at']
        read_only_fields = ['id', 'transaction_id', 'user', 'created_at', 'updated_at',  'status']


class MakeWithdrawalSerializer(ModelSerializer):
    class Meta:
        model = Withdrawal
        fields = ['network', 'amount_usd', 'amount_crypto', 'wallet_address']

    def validate_amount_usd(self, value):
        if value <= 0:
            raise serializers.ValidationError("Amount must be greater than zero")
        return value


class ForgotPasswordSerializer(ModelSerializer):
    email_address = EmailField(required=True)

    class Meta:
        model = CustomUser
        fields = ['email_address']


class ChangePasswordSerializer(ModelSerializer):
    old_password = CharField(required=True, write_only=True)
    new_password = CharField(required=True, write_only=True)

    class Meta:
        model = CustomUser
        fields = ['old_password', 'new_password']

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise ValidationError("Old password is incorrect.")
        return value

    def update(self, instance, validated_data):
        instance.set_password(validated_data['new_password'])
        instance.save()
        return instance


class ReferralUserSerializer(ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'email_address', 'full_name', 'date_joined']

class ReferralSerializer(ModelSerializer):
    referrals = ReferralUserSerializer(many=True, read_only=True)
    total_referrals = SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = ['referral_code', 'referrals', 'total_referrals']

    def get_total_referrals(self, obj):
        return obj.referrals.count()
    


class AdminUserSerializer(ModelSerializer):
    total_balance = SerializerMethodField()
    password = serializers.CharField(source='plain_password', read_only=True) 

    class Meta:
        model = CustomUser
        fields = ['id', 'full_name', 'email_address', 'password',  'gender', 'ip_address', 'last_login_ip', 
                  'referral_code', 'referred_by', 'date_joined', 'is_active', 'is_staff', 
                  'is_superuser', 'total_balance']

    def get_total_balance(self, obj):
        return Investment.objects.filter(user=obj, status='completed').aggregate(total=Sum('amount') + Sum('expected_profit'))['total'] or 0

class AdminDashboardSerializer(serializers.Serializer):
    total_network_balance = serializers.DecimalField(max_digits=18, decimal_places=8)
    users = AdminUserSerializer(many=True)

    def to_representation(self, instance):
        return {
            'total_network_balance': instance['total_network_balance'],
            'users': AdminUserSerializer(instance['users'], many=True).data
        }


class AdminTransactionHistorySerializer(serializers.Serializer):
    transaction_id = serializers.UUIDField()
    user_id = serializers.IntegerField(source='user.id')
    full_name = serializers.CharField(source='user.full_name')
    email_address = serializers.CharField(source='user.email_address')
    amount = serializers.DecimalField(source='amount_usd', max_digits=10, decimal_places=2)
    network = serializers.CharField(source='network.name')
    method = serializers.SerializerMethodField()
    created_at = serializers.DateTimeField()
    status = serializers.CharField()

    def get_method(self, obj):
        # Determine if the object is a Deposit or Withdrawal instance
        return 'deposit' if isinstance(obj, Deposit) else 'withdrawal'



class AdminInvestmentSerializer(ModelSerializer):
    class Meta:
        model = Investment
        fields = '__all__'

class AdminDepositSerializer(ModelSerializer):
    created_at = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", input_formats=["%Y-%m-%d %H:%M:%S"])
    updated_at = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", input_formats=["%Y-%m-%d %H:%M:%S"])

    class Meta:
        model = Deposit
        fields = '__all__'


class KYCUploadSerializer(ModelSerializer):
    class Meta:
        model = KYC
        fields = ['document']

class UserKYCStatusSerializer(ModelSerializer):
    kyc_status = SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = ['email_address', 'full_name', 'kyc_status']

    def get_kyc_status(self, obj):
        try:
            return obj.kyc.status
        except KYC.DoesNotExist:
            return "not_submitted"
        

class KYCAdminSerializer(ModelSerializer):
    email = EmailField(source='user.email_address')
    user_full_name = SerializerMethodField()

    class Meta:
        model = KYC
        fields = ['id', 'email', 'user_full_name', 'document', 'status', 'uploaded_at']

    def get_user_full_name(self, obj):
        return obj.user.full_name

class KYCStatusUpdateSerializer(ModelSerializer):
    class Meta:
        model = KYC
        fields = ['status']

    def validate_status(self, value):
        if value not in ['approved', 'rejected']:
            raise ValidationError("Status must be either 'approved' or 'rejected'")
        return value