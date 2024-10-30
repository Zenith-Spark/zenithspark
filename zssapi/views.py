from django.contrib.auth import authenticate
from django.core.mail import send_mail
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db.models import Sum
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status,permissions
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.views import TokenRefreshView
from .serializers import CustomUserSerializer,InvestmentSerializer,DepositSerializer, MakeDepositSerializer, NetworkSerializer,ReferralUserSerializer, ReferralSerializer, WithdrawalSerializer, MakeWithdrawalSerializer, ChangePasswordSerializer, ForgotPasswordSerializer,  UpdateDepositStatusSerializer, AdminWithdrawalSerializer, InvestmentPlanSerializer, CustomUser,Investment,  InvestmentPlan, Deposit, Withdrawal, Network, Notification, NotificationSerializer
from .utils import generate_random_password
from decimal import Decimal
import requests


class UserRegistration(APIView):
    """ Endpoint for user registration """
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        """ Register a new user """
        serializer = self.serializer_class(data=request.data)
        
        if serializer.is_valid():
            user = serializer.save()
            
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            
            return Response({
                "data": "User created successfully",
                "id": str(user.id),
                "refresh": str(refresh),
                "access": str(refresh.access_token)
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email_address = request.data.get('email_address')
        password = request.data.get('password')

        if not email_address or not password:
            return Response(
                {"error": "Email and password are required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Authenticate the user with email and password
        user = authenticate(request, email_address=email_address, password=password)

        if user is not None:
            if user.is_active:
                # Generate refresh and access tokens
                refresh = RefreshToken.for_user(user)

                # Update user's IP information and save
                user.ip_address = self.get_client_ip(request)
                user.last_login_ip = user.ip_address
                user.save()

                return Response({
                    "id": str(user.id),
                    "email_address": user.email_address,
                    "full_name": user.full_name,
                    "ip_address": user.ip_address,
                    "refresh": str(refresh),
                    "access": str(refresh.access_token)
                }, status=status.HTTP_200_OK)
            else:
                return Response(
                    {"error": "User account is disabled."},
                    status=status.HTTP_403_FORBIDDEN
                )

        # Authentication failed
        return Response(
            {"error": "Invalid credentials"},
            status=status.HTTP_401_UNAUTHORIZED
        )

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            # Get the refresh token from the request body
            refresh_token = request.data.get('refresh_token')
            if not refresh_token:
                return Response({"detail": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)

            # Attempt to blacklist the token
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            print(f"Error during logout: {str(e)}")  # Debugging line
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
        
class ForgotPasswordView(APIView):
    queryset = CustomUser.objects.all()
    serializer_class = ForgotPasswordSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get('email_address')
        users = CustomUser.objects.filter(email_address=email)
        if users.exists():
                user = users.first()
                new_password = generate_random_password() 
                try:
                    send_mail(
                        'Password Reset for Zenith Spark Station',
                        f'Dear {user.email_address},\n\n'
                        'We have received a request to reset your password for Zenith Spark Station.\n\n'
                        f'Your new password is: {new_password}\n\n'
                        'Please use this password to log in to your account. We recommend that you change your password to something more secure as soon as possible.\n\n'
                        'If you have any questions or concerns, please contact us at support@marapolsa.com.\n\n'
                        'Best regards,\n'
                        'The Zenith Spark Station Team',
                        'admin@zenithsparkstation.com',
                        [email],
                    )
                    user.set_password(new_password)
                    user.save()
                    return Response({"message": "New password sent to your email"}, status=status.HTTP_200_OK)
                except:
                    pass
        return Response({"error": "Email not found"}, status=status.HTTP_400_BAD_REQUEST)


# class ChangePassword(APIView):
#     permission_classes = [permissions.IsAuthenticated]
#     serializer_class = ChangePasswordSerializer

#     def post(self, request):
#         serializer = self.serializer_class(data=request.data)
#         if serializer.is_valid():
#             old_password = serializer.validated_data['old_password']
#             new_password = serializer.validated_data['new_password']
#             if not request.user.check_password(old_password):
#                 return Response({'error': 'Old password is incorrect'}, status=status.HTTP_400_BAD_REQUEST)
#             request.user.set_password(new_password)
#             request.user.save()
#             return Response(status=status.HTTP_200_OK)
#         return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED)
    

# views.py
class ChangePassword(APIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ChangePasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(
            instance=request.user,
            data=request.data,
            context={'request': request}
        )
        
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Password changed successfully"}, 
                status=status.HTTP_200_OK
            )
        
        return Response(
            serializer.errors, 
            status=status.HTTP_400_BAD_REQUEST
        )



class UserProfile(APIView):
    """ THIS ENDPOINT IS USED TO GET/UPDATE USER INFO ON THE SERVER """

    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get(self,request):
        userSerializer = self.serializer_class(request.user).data
        return Response({"data":userSerializer},status=status.HTTP_200_OK)
    

    def put(self,request):
        user = request.user
        serializer = self.serializer_class(user,data=request.data,partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response({"data":"ok"},status=status.HTTP_200_OK)

        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
    

class NetworkAPIView(APIView):
    serializer_class = NetworkSerializer
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        networks = Network.objects.all()
        serializer = self.serializer_class(networks, many=True)
        return Response(serializer.data)

class DepositAPIView(APIView):
    serializer_class = DepositSerializer
    secondserializer = MakeDepositSerializer

    def get(self, request):
        deposits = Deposit.objects.filter(user=request.user)
        serializer = self.serializer_class(deposits, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request):
        # Use the second serializer for creating the deposit
        serializer = self.secondserializer(data=request.data)
        if serializer.is_valid():
            deposit = serializer.save(user=request.user)
            self.create_deposit_notification(deposit)
            response_data = self.serializer_class(deposit).data
            return Response(response_data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def create_deposit_notification(self, deposit):
        # Notification message
        message = (
            f"Your deposit of {deposit.amount_usd} USD with Transaction ID: "
            f"{deposit.transaction_id} has been received and is currently pending. "
            f"If status isn't updated in 30 minutes, please contact Support."
        )
        Notification.objects.create(user=deposit.user, message=message)


class AdminUpdateDepositStatusAPIView(APIView):
    permission_classes = [IsAdminUser]
    serializer_class = UpdateDepositStatusSerializer

    def patch(self, request, deposit_id):
        try:
            deposit = Deposit.objects.get(transaction_id=deposit_id)
        except Deposit.DoesNotExist:
            return Response({"error": "Deposit not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = self.serializer_class(deposit, data=request.data, partial=True)

        if serializer.is_valid():
            updated_deposit = serializer.save()
            self.create_status_update_notification(updated_deposit)
            return Response(DepositSerializer(updated_deposit).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    def create_status_update_notification(self, deposit):

        message = f"Your deposit of {deposit.amount_usd} USD with Transaction ID: {deposit.transaction_id} has been {deposit.status}."

        Notification.objects.create(user=deposit.user, message=message)

class WithdrawalAPIView(APIView):
    serializer_class = WithdrawalSerializer
    second_serializer = MakeWithdrawalSerializer

    def get(self, request):
        withdrawals = Withdrawal.objects.filter(user=request.user)
        serializer = self.serializer_class(withdrawals, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = self.second_serializer(data=request.data)
        if serializer.is_valid():
            withdrawal = serializer.save(user=request.user)
            self.create_withdrawal_notification(withdrawal)
            response_data = self.serializer_class(withdrawal).data
            withdrawal_id = response_data.get('transaction_id')
            return Response(response_data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def create_withdrawal_notification(self, withdrawal):
        message = f"Your withdrawal request of {withdrawal.amount_usd} USD with Transaction ID: {withdrawal.transaction_id} has been received and is currently pending. If the status isn't updated within 24 hours, please contact Support via the chatbot on your screen."
        Notification.objects.create(user=withdrawal.user, message=message)

class AdminWithdrawalConfirmationView(APIView):
    serializer_class = AdminWithdrawalSerializer
    permission_classes = [permissions.IsAdminUser]

    def post(self, request, withdrawal_id):
        try:
            withdrawal = Withdrawal.objects.get(transaction_id=withdrawal_id)
        except Withdrawal.DoesNotExist:
            return Response({'error': 'Withdrawal not found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = self.serializer_class(withdrawal, data=request.data, partial=True)
        if serializer.is_valid():
            updated_withdrawal = serializer.save()
            self.create_confirmation_notification(updated_withdrawal)
            return Response(WithdrawalSerializer(updated_withdrawal).data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def create_confirmation_notification(self, withdrawal):
        if withdrawal.status == 'completed':
            message = f"Your withdrawal of {withdrawal.amount_usd} USD with Transaction ID: {withdrawal.transaction_id} has been completed. The funds should now be in your specified wallet."
        else:  # status is 'failed'
            message = f"Your withdrawal of {withdrawal.amount_usd} USD with Transaction ID: {withdrawal.transaction_id} has failed. Please contact support via the chatbot on your screen. for more information."
        Notification.objects.create(user=withdrawal.user, message=message)

class InvestmentPlanListView(APIView):
    serializer_class = InvestmentPlanSerializer

    def get(self, request):
        plans = InvestmentPlan.objects.filter(is_active=True)
        serializer = self.serializer_class(plans, many=True)
        return Response(serializer.data)

class InvestmentPlanAdminView(APIView):
    permission_classes = [IsAdminUser]
    serializer_class = InvestmentPlanSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        try:
            plan = InvestmentPlan.objects.get(pk=pk)
        except InvestmentPlan.DoesNotExist:
            return Response({'error': 'Investment plan not found'}, status=status.HTTP_404_NOT_FOUND)
        serializer = self.serializer_class(plan, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class InvestmentAPIView(APIView):
    serializer_class = InvestmentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        investments = Investment.objects.filter(user=request.user)
        serializer = self.serializer_class(investments, many=True)
        return Response(serializer.data)

    def post(self, request):
        data = request.data
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            investment_plan = serializer.validated_data['investment_plan']
            amount = serializer.validated_data['amount']

            # Validate amount against plan limits
            if amount < investment_plan.minimum_amount or amount > investment_plan.maximum_amount:
                return Response({
                    'error': f'Amount must be between {investment_plan.minimum_amount} and {investment_plan.maximum_amount}'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Calculate expected profit and return time
            profit_rate = float(investment_plan.profit_percentage) / 100
            expected_profit = amount * Decimal(profit_rate)
            return_time = timezone.now() + timezone.timedelta(days=investment_plan.duration_days)

            investment = serializer.save(user=request.user, expected_profit=expected_profit, return_time=return_time)
            self.create_investment_notification(investment)
            self.create_admin_notification(investment)

            return Response(self.serializer_class(investment).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def create_investment_notification(self, investment):
        message = f"Your investment of ${investment.amount} in {investment.investment_plan.name} has been created and is pending approval."
        Notification.objects.create(user=investment.user, message=message)

    def create_admin_notification(self, investment):
        admins = CustomUser.objects.filter(is_staff=True)
        message = f"New investment of ${investment.amount} by {investment.user.email_address} needs approval."
        for admin in admins:
            Notification.objects.create(user=admin, message=message)

class InvestmentAdminView(APIView):
    permission_classes = [IsAdminUser]
    serializer_class = InvestmentSerializer

    def get(self, request):
        investments = Investment.objects.all()
        serializer = self.serializer_class(investments, many=True)
        return Response(serializer.data)

    def put(self, request, pk):
        try:
            investment = Investment.objects.get(pk=pk)
        except Investment.DoesNotExist:
            return Response({'error': 'Investment not found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = self.serializer_class(investment, data=request.data, partial=True)
        if serializer.is_valid():
            updated_investment = serializer.save()
            self.create_status_notification(updated_investment)
            return Response(self.serializer_class(updated_investment).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def create_status_notification(self, investment):
        if investment.status == 'active':
            message = f"Your investment of ${investment.amount} in {investment.investment_plan.name} has been confirmed and is now active."
        elif investment.status == 'completed': 
            message = f"Your investment of ${investment.amount} in {investment.investment_plan.name} has been completed successfully."
        elif investment.status == 'failed':
            message = f"Your investment of ${investment.amount} in {investment.investment_plan.name} has been completed successfully."
        elif investment.status == 'cancelled':
            message = f"Your investment of ${investment.amount} in {investment.investment_plan.name} has been cancelled."
        Notification.objects.create(user=investment.user, message=message)
    
class NotificationAPIView(APIView):
    serializer_class = NotificationSerializer
    def get(self, request):
        notifications = Notification.objects.filter(user=request.user)
        serializer = self.serializer_class(notifications, many=True)
        return Response(serializer.data)

    def put(self, request, notification_id):
        try:
            notification = Notification.objects.get(id=notification_id, user=request.user)
        except Notification.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        notification.is_read = True
        notification.save()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
class NetworkTransactionHistoryAPIView(APIView):

    def get(self, request, network_name):
        try:
            network = Network.objects.get(name=network_name)
        except Network.DoesNotExist:
            return Response({"error": "Network not found"}, status=status.HTTP_404_NOT_FOUND)

        deposits = Deposit.objects.filter(user=request.user, network=network)
        withdrawals = Withdrawal.objects.filter(user=request.user, network=network)

        deposit_serializer = DepositSerializer(deposits, many=True)
        withdrawal_serializer = WithdrawalSerializer(withdrawals, many=True)

        return Response({
            "network": NetworkSerializer(network).data,
            "deposits": [
                {
                    "transaction_id": item['transaction_id'],
                    "amount": item['amount_usd'],
                    "status": item['status'],
                    "date": item['date'],
                }
                for item in deposit_serializer.data
            ],
            "withdrawals": [
                {
                    "transaction_id": item['transaction_id'],
                    "amount": item['amount_usd'],
                    "status": item['status'],
                    "date": item['date'],
                }
                for item in withdrawal_serializer.data
            ]
        })


class ExchangeRatesAPIView(APIView):

    def get(self, request):
        amount_usd = request.query_params.get('amount_usd')
        network = request.query_params.get('network')

        if not amount_usd or not network:
            return Response({"error": "Both amount_usd and network are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            amount_usd = float(amount_usd)
        except ValueError:
            return Response({"error": "Invalid amount_usd value."}, status=status.HTTP_400_BAD_REQUEST)

        # Get the cryptocurrency symbol for the network
        try:
            crypto_symbol = Network.objects.get(name=network).symbol.lower()
        except Network.DoesNotExist:
            return Response({"error": "Invalid network."}, status=status.HTTP_400_BAD_REQUEST)

        # Check cache first
        cache_key = f"exchange_rates_{crypto_symbol}"
        exchange_rates = cache.get(cache_key)

        if not exchange_rates:
            # Make a request to CoinGecko API
            coingecko_url = "https://api.coingecko.com/api/v3/exchange_rates"
            response = requests.get(coingecko_url)

            if response.status_code != 200:
                return Response({"error": "Failed to fetch exchange rates."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            exchange_rates = response.json()['rates']

            # Cache the results for 5 minutes
            cache.set(cache_key, exchange_rates, 300)

        if crypto_symbol not in exchange_rates:
            return Response({"error": "Exchange rate not available for this network."}, status=status.HTTP_400_BAD_REQUEST)

        usd_rate = exchange_rates['usd']['value']
        crypto_rate = exchange_rates[crypto_symbol]['value']
        
        # Calculate the exchange rate (crypto per USD)
        exchange_rate = usd_rate / crypto_rate

        # Calculate the amount in crypto
        amount_crypto = amount_usd * exchange_rate

        return Response({
            "amount_usd": amount_usd,
            "amount_crypto": amount_crypto,
            "network": network,
            "exchange_rate": exchange_rate
        }, status=status.HTTP_200_OK)


class UpdateNetworkBalanceAPIView(APIView):

    def get(self, request):
        network_id = request.query_params.get('network_id')
        transaction_id = request.query_params.get('transaction_id')

        if network_id:
            try:
                network = Network.objects.get(id=network_id)
                return Response({'network': network.name, 'balance': network.balance}, status=status.HTTP_200_OK)
            except Network.DoesNotExist:
                return Response({'error': 'Network not found'}, status=status.HTTP_404_NOT_FOUND)
        elif transaction_id:
            deposit = Deposit.objects.filter(transaction_id=transaction_id).first()
            withdrawal = Withdrawal.objects.filter(transaction_id=transaction_id).first()
            
            if deposit:
                return Response({'network': deposit.network.name, 'balance': deposit.network.balance}, status=status.HTTP_200_OK)
            elif withdrawal:
                return Response({'network': withdrawal.network.name, 'balance': withdrawal.network.balance}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Transaction not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            networks = Network.objects.all()
            balances = [{'network': network.name, 'balance': network.balance} for network in networks]
            return Response(balances, status=status.HTTP_200_OK)
        
    def post(self, request):
        transaction_id = request.data.get('transaction_id')  
        if not transaction_id:
            return Response({'error': 'Transaction ID is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Try to find the transaction in both Deposit and Withdrawal models
        deposit = Deposit.objects.filter(transaction_id=transaction_id, status='completed').first()
        withdrawal = Withdrawal.objects.filter(transaction_id=transaction_id, status='completed').first()

        if deposit:
            return self.handle_deposit(deposit)
        elif withdrawal:
            return self.handle_withdrawal(withdrawal)
        else:
            return Response({'error': 'Completed transaction not found'}, status=status.HTTP_404_NOT_FOUND)

    def handle_deposit(self, deposit):
        try:
            self.update_network_balance(deposit.network, deposit.amount_usd, is_deposit=True)
            return Response({'message': 'Network balance updated successfully for deposit'}, status=status.HTTP_200_OK)
        except ValidationError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def handle_withdrawal(self, withdrawal):
        try:
            self.update_network_balance(withdrawal.network, withdrawal.amount_usd, is_deposit=False)
            return Response({'message': 'Network balance updated successfully for withdrawal'}, status=status.HTTP_200_OK)
        except ValidationError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


    def update_network_balance(self, network, amount, is_deposit):
        if amount is None or amount <= 0:
            raise ValidationError("Invalid transaction amount")
        if is_deposit:
            network.balance += amount
        else:
            if network.balance < amount:
                raise ValidationError("Insufficient network balance for this withdrawal")
            network.balance -= amount
        network.save()

class TotalBalanceView(APIView):
    def get(self, request):
        total_balance = Network.objects.aggregate(total=Sum('balance'))['total'] or 0
        return Response({'total_balance': total_balance}, status=status.HTTP_200_OK)
    


class ReferralView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ReferralSerializer
    
    def get(self, request):
        """Get current user's referral information"""
        serializer = self.serializer_class(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)

class ApplyReferralCode(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        referral_code = request.data.get('referral_code')
        
        if not referral_code:
            return Response({"error": "Referral code is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Check if user already has a referrer
        if request.user.referred_by:
            return Response({"error": "You have already used a referral code"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            referrer = CustomUser.objects.get(referral_code=referral_code)
            # Prevent self-referral
            if referrer == request.user:
                return Response(
                    {"error": "You cannot use your own referral code"}, status=status.HTTP_400_BAD_REQUEST)

            request.user.referred_by = referrer
            request.user.save()

            # Create notification for referrer
            Notification.objects.create(user=referrer, message=f"{request.user.full_name} has used your referral code!")

            return Response({"message": "Referral code applied successfully"}, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            return Response({"error": "Invalid referral code"}, status=status.HTTP_404_NOT_FOUND)

class AdminReferralView(APIView):
    permission_classes = [IsAdminUser]
   
    def get(self, request):
        """Get all referral information for admin"""
        try:
            # Get all users who were referred (excluding staff)
            users = CustomUser.objects.exclude(is_staff=True).filter(referred_by__isnull=False)

            referral_data = []
            for user in users:
                user_info = {
                    'full_name': user.full_name,
                    'ip_address': user.ip_address,
                    'email_address': user.email_address,
                    'referred_by': {
                        'full_name': user.referred_by.full_name,
                    } if user.referred_by else None,
                    'date_joined': user.date_joined,
                }
                referral_data.append(user_info)
            return Response(referral_data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class MyReferralCodeView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            'referral_code': user.referral_code,
            'total_referrals': user.referrals.count()
        })

class UserReferralDetailsView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get detailed information about users who used the current user's referral code"""
        try:
            user = request.user
            referred_users = user.referrals.all()

            # Get detailed information about referred users
            referred_users_data = []
            for referred_user in referred_users:
                referred_users_data.append({
                    'id': referred_user.id,
                    'full_name': referred_user.full_name,
                    'email': referred_user.email_address,
                    'ip_address': referred_user.ip_address,
                    'date_joined': referred_user.date_joined,
                    'is_active': referred_user.is_active,
                })

            return Response(referred_users_data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {'error': f'An error occurred: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )