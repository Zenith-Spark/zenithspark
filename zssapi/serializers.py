from rest_framework.serializers import ModelSerializer, EmailField, CharField, IntegerField, SerializerMethodField
from .models import CustomUser, Investment, Deposit, Withdrawal, Network, Notification, InvestmentPlan
from rest_framework.exceptions import ValidationError
from rest_framework import serializers
 



class CustomUserSerializer(ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('id', 'full_name', 'email_address', 'password', 'gender', 'ip_address', 'last_login_ip', 'date_joined',  'referral_code', 'referred_by')
        extra_kwargs = {'password': {'write_only': True}}
    
    def create(self, validated_data):
        # Use the manager's create_user method to handle password hashing
        user = CustomUser.objects.create_user(
            email_address=validated_data['email_address'],
            password=validated_data['password'],
            full_name=validated_data.get('full_name'),
            ip_address=validated_data.get('ip_address'),
            last_login_ip=validated_data.get('last_login_ip'),
            referral_code=validated_data.get('referral_code'),
            referred_by=validated_data.get('referred_by'),
        )
        return user

    def update(self, instance, validated_data):
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

# class InvestmentSerializer(ModelSerializer):
#     class Meta:
#         model = Investment
#         fields = ['id', 'user', 'plan', 'amount', 'expected_profit', 'investment_time', 'return_time', 'status']
#         read_only_fields = ['id', 'user', 'investment_time', 'status']

class InvestmentPlanSerializer(ModelSerializer):
    class Meta:
        model = InvestmentPlan
        fields = '__all__'

class InvestmentSerializer(ModelSerializer):
    plan_name = CharField(source='investment_plan.name', read_only=True)
    duration_days = IntegerField(source='investment_plan.duration_days', read_only=True)
    
    class Meta:
        model = Investment
        fields = ['id', 'user', 'investment_plan', 'plan_name', 'payment_method', 'amount', 'expected_profit', 'investment_time', 'return_time', 'status', 'duration_days']
        read_only_fields = ['id', 'user', 'expected_profit', 'investment_time', 'return_time', 'status']

class NetworkSerializer(ModelSerializer):
    class Meta:
        model = Network
        fields = ['id', 'name', 'symbol', 'wallet_address']

class DepositSerializer(ModelSerializer):
    class Meta:
        model = Deposit
        fields = ['id', 'transaction_id', 'user', 'network', 'amount_usd', 'amount_crypto', 'status', 'date']
        read_only_fields = ['id', 'transaction_id', 'user', 'date', 'status']

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
    class Meta:
        model = Withdrawal
        fields = ['id', 'transaction_id', 'user', 'network', 'amount_usd', 'amount_crypto', 'wallet_address', 'status', 'date']
        read_only_fields = ['id', 'transaction_id', 'user', 'date', 'status']


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

# serializers.py
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