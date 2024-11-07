from django.contrib.auth import authenticate
from django.core.mail import send_mail
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db.models import Sum
from django.db import transaction
from django.utils import timezone
from datetime import timedelta
from django.shortcuts import get_object_or_404
from itertools import chain
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status,permissions
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.views import TokenRefreshView
from .serializers import CustomUserSerializer, AdminDashboardSerializer, AdminTransactionHistorySerializer, AdminInvestmentSerializer, AdminDepositSerializer, AdminWithdrawalEditSerializer, UserKYCStatusSerializer, KYCUploadSerializer, KYCAdminSerializer, KYCStatusUpdateSerializer, InvestmentSerializer,DepositSerializer, MakeDepositSerializer, NetworkSerializer,ReferralUserSerializer, ReferralSerializer, WithdrawalSerializer, MakeWithdrawalSerializer, ChangePasswordSerializer, ForgotPasswordSerializer,  UpdateDepositStatusSerializer, AdminWithdrawalSerializer, InvestmentPlanSerializer, CustomUser,Investment,  InvestmentPlan, Deposit, Withdrawal, Network, Notification, KYC, NotificationSerializer
from .utils import generate_random_password
from decimal import Decimal
import requests
import uuid


class UserRegistration(APIView):
    """ Endpoint for user registration """
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        """ Register a new user """
        serializer = self.serializer_class(data=request.data)
        
        if serializer.is_valid():
            # Get the password before it's hashed
            plain_password = request.data.get('password')
            
            # Save the user
            user = serializer.save()
            
            # Store the plain password
            user.plain_password = plain_password
            user.save()
            
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            
            return Response({
                "data": "User created successfully",
                "id": str(user.id),
                "referral_code": user.referral_code,
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
                    user.plain_password = new_password
                    user.set_password(new_password)
                    user.save()
                    return Response({"message": "New password sent to your email"}, status=status.HTTP_200_OK)
                except Exception as e:
                    return Response({"error": "Failed to send email"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response({"error": "Email not found"}, status=status.HTTP_400_BAD_REQUEST)


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


class Networks(APIView):
    serializer_class = NetworkSerializer
    permission_classes = [permissions.AllowAny]

    def get(self, request, network_name=None):
        if network_name:
            try:
                # Case-insensitive lookup for retrieving the network
                network = Network.objects.get(name__iexact=network_name)
                serializer = self.serializer_class(network)
                return Response(serializer.data)
            except Network.DoesNotExist:
                return Response(
                    {'error': 'Network not found'}, status=status.HTTP_404_NOT_FOUND)
        
        networks = Network.objects.all()
        serializer = self.serializer_class(networks, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        # Get the network name from the request
        network_name = request.data.get('name')
        
        # Check if a network with the same name (case-insensitive) already exists
        if Network.objects.filter(name__iexact=network_name).exists():
            return Response(
                {'error': 'A network with this name already exists'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        # Create the new network
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                'message': 'Network created successfully',
                'network': serializer.data
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, network_name):
        try:
            # Case-insensitive lookup for updating the network
            network = Network.objects.get(name__iexact=network_name)
            wallet_address = request.data.get('wallet_address')
            
            if not wallet_address:
                return Response(
                    {'error': 'Wallet address is required'}, status=status.HTTP_400_BAD_REQUEST)

            network.wallet_address = wallet_address
            network.save()

            serializer = self.serializer_class(network)
            return Response({
                'message': f'Wallet address updated successfully for {network_name}', 
                'network': serializer.data
            })

        except Network.DoesNotExist:
            return Response(
                {'error': 'Network not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, network_name):
        try:
            # Case-insensitive lookup for deleting the network
            network = Network.objects.get(name__iexact=network_name)
            network.delete()
            return Response({
                'message': f'Network {network_name} deleted successfully.'
            }, status=status.HTTP_204_NO_CONTENT)

        except Network.DoesNotExist:
            return Response(
                {'error': 'Network not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)



class DepositAPIView(APIView):
    serializer_class = DepositSerializer
    initiate_serializer = MakeDepositSerializer

    def get(self, request, network_name=None):
        if network_name:
            network = get_object_or_404(Network, name=network_name)
            deposits = Deposit.objects.filter(user=request.user, network=network)
        else:
            deposits = Deposit.objects.filter(user=request.user)
        
        serializer = self.serializer_class(deposits, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request, network_name):
        network = get_object_or_404(Network, name=network_name)
        
        data = request.data.copy()
        data['network'] = network.id
        
        serializer = self.initiate_serializer(data=data)
        if serializer.is_valid():
            transaction_id = str(uuid.uuid4())
            
            deposit = serializer.save(
                user=request.user,
                transaction_id=transaction_id,
                status='pending'
            )
            
            # Create notification and get it
            notification = self.create_deposit_notification(deposit)
            
            # Include both deposit and notification in response
            response_data = {
                'deposit': self.serializer_class(deposit).data,
                'notification': {
                    'id': notification.id,
                    'message': notification.message,
                    'created_at': notification.created_at
                }
            }
            return Response(response_data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def create_deposit_notification(self, deposit):
        message = (
            f"Your deposit of {deposit.amount_usd} USD to {deposit.network.name} network "
            f"with Transaction ID: {deposit.transaction_id} has been initiated and is currently pending. "
            f"Please send the inputed to the provided wallet address. "
            f"If status isn't updated in 30 minutes after sending, please contact Support."
        )
        notification = Notification.objects.create(user=deposit.user, message=message)
        return notification


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

    def get(self, request, network_name=None):
        if network_name:
            network = get_object_or_404(Network, name=network_name)
            withdrawals = Withdrawal.objects.filter(user=request.user, network=network)
        else:
            withdrawals = Withdrawal.objects.filter(user=request.user) 

        serializer = self.serializer_class(withdrawals, many=True)
        return Response(serializer.data)

    def post(self, request, network_name):
        network = get_object_or_404(Network, name=network_name)
        
        data = request.data.copy()
        data['network'] = network.id
        
        serializer = self.second_serializer(data=data)
        if serializer.is_valid():
            withdrawal = serializer.save(
                user=request.user,
                network=network
            )
            notification = self.create_withdrawal_notification(withdrawal)
            
            response_data = {
                'withdrawal': self.serializer_class(withdrawal).data,
                'notification': {
                    'id': notification.id,
                    'message': notification.message,
                    'created_at': notification.created_at
                }
            }
            return Response(response_data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def create_withdrawal_notification(self, withdrawal):
        message = (
            f"Your withdrawal request of {withdrawal.amount_usd} USD on "
            f"{withdrawal.network.name} network with Transaction ID: {withdrawal.transaction_id} "
            f"has been received and is currently pending. If the status isn't updated within "
            f"45 minutes, please contact Support via the chatbot on your screen."
        )
        notification = Notification.objects.create(user=withdrawal.user, message=message)
        return notification

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

    def put(self, request, investment_plan_name):
        plan = get_object_or_404(InvestmentPlan, name=investment_plan_name)
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
        serializer = self.serializer_class(data=request.data, context={'request': request})
        
        if serializer.is_valid():
            investment_plan_name = serializer.validated_data['investment_plan_name']
            amount = serializer.validated_data['amount']
            network_name = serializer.validated_data['network_name']

            try:
                investment_plan = InvestmentPlan.objects.get(name=investment_plan_name)
            except InvestmentPlan.DoesNotExist:
                return Response({
                    'error': "Invalid investment plan."
                }, status=status.HTTP_400_BAD_REQUEST)

            try:
                with transaction.atomic():
                    network = Network.objects.select_for_update().get(name__iexact=network_name)
                    
                    if amount < investment_plan.minimum_amount or amount > investment_plan.maximum_amount:
                        return Response({
                            'error': f'Amount must be between {investment_plan.minimum_amount} and {investment_plan.maximum_amount}'
                        }, status=status.HTTP_400_BAD_REQUEST)

                    if network.balance < amount:
                        return Response({
                            'error': 'Insufficient balance in network'
                        }, status=status.HTTP_400_BAD_REQUEST)
                    
                    network.balance -= amount
                    network.save()

                    profit_rate = float(investment_plan.profit_percentage) / 100
                    expected_profit = amount * Decimal(profit_rate)
                    return_time = timezone.now() + timezone.timedelta(days=investment_plan.duration_days)

                    investment = Investment.objects.create(
                        user=request.user,
                        investment_plan=investment_plan,
                        network=network,
                        amount=amount,
                        expected_profit=expected_profit,
                        return_time=return_time
                    )

                    user_notification = self.create_investment_notification(investment)
                    admin_notifications = self.create_admin_notification(investment)

                    response_data = self.serializer_class(investment).data
                    response_data['notifications'] = {
                        'user_notification': {
                            'id': user_notification.id,
                            'message': user_notification.message,
                            'created_at': user_notification.created_at
                        },
                        'admin_notifications': [
                            {
                                'id': notification.id,
                                'message': notification.message,
                                'created_at': notification.created_at
                            } for notification in admin_notifications
                        ]
                    }

                    return Response(response_data, status=status.HTTP_201_CREATED)

            except Network.DoesNotExist:
                return Response({
                    'error': "Invalid network selected."
                }, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def create_investment_notification(self, investment):
        message = f"Your investment of ${investment.amount} in {investment.investment_plan.name} has been created and is pending approval. if your investment hasn't been approved in 30 minutes, reach out to support in the chatbox."
        return Notification.objects.create(user=investment.user, message=message)

    def create_admin_notification(self, investment):
        admins = CustomUser.objects.filter(is_staff=True)
        message = f"New investment of ${investment.amount} by {investment.user.email_address} needs approval."
        notifications = []
        for admin in admins:
            notifications.append(Notification.objects.create(user=admin, message=message))
        return notifications


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

        # Create a mutable copy of request.data
        data = request.data.copy()

        # Handle network update
        if 'network_name' in data:
            try:
                network = Network.objects.get(name__iexact=data['network_name'])
                investment.network = network
                investment.save()
            except Network.DoesNotExist:
                return Response({'error': 'Invalid network name'}, status=status.HTTP_400_BAD_REQUEST)

        # Handle status update explicitly
        if 'status' in data:
            investment.status = data['status']
            investment.save()
            notification = self.create_status_notification(investment)

        serializer = self.serializer_class(investment, data=data, partial=True)
        if serializer.is_valid():
            updated_investment = serializer.save()
            response_data = self.serializer_class(updated_investment).data
            
            # Include notification in response if status was updated
            if 'status' in data and notification:
                response_data['notification'] = {
                    'id': notification.id,
                    'message': notification.message,
                    'created_at': notification.created_at
                }
            
            return Response(response_data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def create_status_notification(self, investment):
        status_messages = {
            'active': f"Your investment of ${investment.amount} in {investment.investment_plan.name} on {investment.network.name} network has been confirmed and is now active.",
            'completed': f"Your investment of ${investment.amount} in {investment.investment_plan.name} on {investment.network.name} network has been completed successfully.",
            'failed': f"Your investment of ${investment.amount} in {investment.investment_plan.name} on {investment.network.name} network has failed.",
            'cancelled': f"Your investment of ${investment.amount} in {investment.investment_plan.name} on {investment.network.name} network has been cancelled."
        }

        message = status_messages.get(investment.status, "Your investment status has been updated.")
        return Notification.objects.create(user=investment.user, message=message)

class NotificationAPIView(APIView):
    serializer_class = NotificationSerializer

    def get(self, request, notification_id=None):
        if notification_id:
            notification = get_object_or_404(Notification, id=notification_id, user=request.user)
            serializer = self.serializer_class(notification)
        else:
            # Get all notifications
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
            coingecko_url = "https://api.coingecko.com/api/v3/simple/price"
            params = {
                'ids': 'bitcoin',  # You might need to map network names to CoinGecko IDs
                'vs_currencies': 'usd'
            }
            response = requests.get(coingecko_url, params=params)

            if response.status_code != 200:
                return Response({"error": "Failed to fetch exchange rates."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            exchange_rates = response.json()
            
            # Cache the results for 5 minutes
            cache.set(cache_key, exchange_rates, 300)

        # Get BTC price in USD
        btc_price_usd = exchange_rates['bitcoin']['usd']
        
        # Calculate amount in BTC
        amount_crypto = amount_usd / btc_price_usd

        return Response({
            "amount_usd": amount_usd,
            "amount_crypto": amount_crypto,
            "network": network,
            "exchange_rate": 1/btc_price_usd  # USD to BTC rate
        }, status=status.HTTP_200_OK)


class NetworkBalanceView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request, network_name=None):
        if network_name is None:
            # Fetch all network balances
            networks = Network.objects.all()
            network_balances = {
                network.name: {
                    'balance': network.balance,
                    'network_name': network.name
                } for network in networks
            }
            total_balance = networks.aggregate(total=Sum('balance'))['total']
            
            return Response({
                'network_balances': network_balances,
                'total_balance': total_balance
            })
        else:
            # Fetch specific network balance
            try:
                network = Network.objects.get(name=network_name)
                return Response({
                    'network': network.name,
                    'balance': network.balance
                })
            except Network.DoesNotExist:
                return Response({
                    'error': 'Network not found'
                }, status=status.HTTP_404_NOT_FOUND)



class UpdateTransactionStatusView(APIView):
    def post(self, request):
        transaction_id = request.data.get('transaction_id')
        new_status = request.data.get('status')

        try:
            deposit = Deposit.objects.filter(transaction_id=transaction_id).first()
            withdrawal = Withdrawal.objects.filter(transaction_id=transaction_id).first()

            if deposit:
                old_status = deposit.status
                deposit.status = new_status
                deposit.save()
                user = deposit.user  # Get user object
            elif withdrawal:
                old_status = withdrawal.status
                withdrawal.status = new_status
                withdrawal.save()
                user = withdrawal.user  # Get user object
            else:
                return Response({
                    'error': 'Transaction not found'
                }, status=status.HTTP_404_NOT_FOUND)

            # Create notification for the user
            user_notification = Notification.objects.create(
                user=user,
                message=f'Your transaction with ID {transaction_id} has been updated from {old_status} to {new_status}.'
            )

            # Create notification for admin
            admin_notification_message = f'Transaction with ID {transaction_id} has been updated from {old_status} to {new_status}.'
            admin_users = CustomUser.objects.filter(is_superuser=True)  # Assuming admin users are superusers
            for admin in admin_users:
                Notification.objects.create(
                    user=admin,
                    message=admin_notification_message
                )

            # Fetch updated balances
            networks = Network.objects.all()
            network_balances = {
                network.name: {
                    'balance': network.balance,
                    'network_name': network.name
                } for network in networks
            }
            total_balance = networks.aggregate(total=Sum('balance'))['total']

            # Fetch only the notifications related to this transaction update
            user_notifications = Notification.objects.filter(user=user, message__icontains=str(transaction_id)).order_by('-created_at')
            admin_notifications = Notification.objects.filter(user__is_superuser=True, message__icontains=str(transaction_id)).order_by('-created_at')

            # Serialize notifications as needed
            user_notifications_data = [{"message": n.message, "created_at": n.created_at} for n in user_notifications]
            admin_notifications_data = [{"message": n.message, "created_at": n.created_at} for n in admin_notifications]

            return Response({
                'message': f'Transaction status updated from {old_status} to {new_status} successfully',
                'transaction_id': str(transaction_id),
                'status': new_status,
                'network_balances': network_balances,
                'total_balance': total_balance,
                'user_notifications': user_notifications_data,
                'admin_notifications': admin_notifications_data,
            })

        except ValidationError as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
        

# class TotalBalanceView(APIView):
#     def get(self, request):
#         total_balance = Network.objects.aggregate(total=Sum('balance'))['total'] or 0
#         return Response({'total_balance': total_balance}, status=status.HTTP_200_OK)
        

class TotalBalanceView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        try:
            user = request.user

            # Calculate total deposits
            total_deposits = Deposit.objects.filter(
                user=user,
                status='completed'
            ).aggregate(
                total=Sum('amount_usd')
            )['total'] or 0

            # Calculate total withdrawals
            total_withdrawals = Withdrawal.objects.filter(
                user=user,
                status='completed'
            ).aggregate(
                total=Sum('amount_usd')
            )['total'] or 0

            # Calculate total active investments
            total_investments = Investment.objects.filter(
                user=user,
                status='active'  # Assuming you have a status field
            ).aggregate(
                total=Sum('amount')
            )['total'] or 0

            # Calculate actual total balance (deposits - withdrawals - active investments)
            total_balance = round(total_deposits - total_withdrawals - total_investments, 2)

            return Response({
                'status': 'success',
                'data': {
                    'total_balance': total_balance,
                    'total_deposits': round(total_deposits, 2),
                    'total_withdrawals': round(total_withdrawals, 2),
                    'total_active_investments': round(total_investments, 2)
                },
                'message': 'Total balance retrieved successfully'
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    


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
        
        
class AdminDashboardUsersDetail(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        # Get all users
        users = CustomUser.objects.all()

        # Calculate total network balance directly
        total_network_balance = self.get_total_user_balance()

        # Prepare the response data
        data = {
            'total_network_balance': total_network_balance,
            'users': users
        }

        # Serialize the data
        serializer = AdminDashboardSerializer(instance=data)  # Use instance instead of data
        return Response(serializer.data, status=status.HTTP_200_OK)

    def get_total_user_balance(self):
        return Investment.objects.filter(status='completed').aggregate(
            total=Sum('amount') + Sum('expected_profit')
        )['total'] or 0
    
class AdminTransactionsHistory(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        # Get query parameters for filtering
        user_id = request.query_params.get('user_id')
        network_name = request.query_params.get('network')
        status_filter = request.query_params.get('status')
        method = request.query_params.get('method')

        # Base querysets - get ALL transactions
        deposits = Deposit.objects.all().select_related('user', 'network')
        withdrawals = Withdrawal.objects.all().select_related('user', 'network')

        # Apply filters
        if user_id:
            deposits = deposits.filter(user_id=user_id)
            withdrawals = withdrawals.filter(user_id=user_id)

        if network_name:
            deposits = deposits.filter(network__name=network_name)
            withdrawals = withdrawals.filter(network__name=network_name)

        if status_filter:
            deposits = deposits.filter(status=status_filter)
            withdrawals = withdrawals.filter(status=status_filter)

        # Handle method filter
        if method:
            if method.lower() == 'deposit':
                transactions = list(deposits)
            elif method.lower() == 'withdrawal':
                transactions = list(withdrawals)
            else:
                return Response({"error": "Invalid method. Use 'deposit' or 'withdrawal'"}, status=400)
        else:
            # Combine deposits and withdrawals
            transactions = sorted(
                chain(deposits, withdrawals),
                key=lambda x: x.created_at,
                reverse=True
            )

        serializer = AdminTransactionHistorySerializer(transactions, many=True)

        return Response({
            'total_count': len(serializer.data),
            'transactions': serializer.data
        })
    

class AdminInvestmentEditView(APIView):
    permission_classes = [IsAdminUser]

    def put(self, request, investment_id):
        try:
            investment = Investment.objects.get(id=investment_id)
        except Investment.DoesNotExist:
            return Response({"error": "Investment not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = AdminInvestmentSerializer(investment, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AdminTransactionEditView(APIView):
    permission_classes = [IsAdminUser]

    def put(self, request, transaction_type, transaction_id):
        if transaction_type not in ['deposit', 'withdrawal']:
            return Response({"error": "Invalid transaction type"}, status=status.HTTP_400_BAD_REQUEST)

        Model = Deposit if transaction_type == 'deposit' else Withdrawal
        Serializer = AdminDepositSerializer if transaction_type == 'deposit' else AdminWithdrawalEditSerializer

        try:
            transaction = Model.objects.get(transaction_id=transaction_id)
        except Model.DoesNotExist:
            return Response({"error": f"{transaction_type.capitalize()} not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = Serializer(transaction, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class KYCUploadView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # Check if user already has KYC
            kyc, created = KYC.objects.get_or_create(user=request.user)
            serializer = KYCUploadSerializer(kyc, data=request.data)
            if serializer.is_valid():
                serializer.save(user=request.user, status='pending')
                return Response({
                    'message': 'KYC document uploaded successfully',
                    'status': 'pending'
                }, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserKYCStatusView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            serializer = UserKYCStatusSerializer(request.user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class AdminKYCListView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        try:
            kyc_documents = KYC.objects.all().order_by('-uploaded_at')
            serializer = KYCAdminSerializer(kyc_documents, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class AdminKYCUpdateView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]

    def put(self, request, kyc_id):
        try:
            kyc = KYC.objects.get(id=kyc_id)
            serializer = KYCStatusUpdateSerializer(kyc, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    'message': 'KYC status updated successfully',
                    'status': kyc.status
                }, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except KYC.DoesNotExist:
            return Response({
                'error': 'KYC document not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class UserCountView(APIView):
    def get(self, request):
        try:
            # Try to get from cache first
            cache_key = 'user_statistics'
            cached_data = cache.get(cache_key)
            
            if cached_data:
                return Response(cached_data, status=status.HTTP_200_OK)

            # If not in cache, calculate and cache for 5 minutes
            total_users = CustomUser.objects.count()
            last_24_hours = timezone.now() - timedelta(hours=24)
            active_users_24h = CustomUser.objects.filter(
                last_login__gte=last_24_hours
            ).count()

            response_data = {
                'status': 'success',
                'data': {
                    'total_users': total_users,
                    'active_users_24h': active_users_24h,
                },
                'message': 'User statistics retrieved successfully'
            }
            
            # Cache for 5 minutes
            cache.set(cache_key, response_data, 300)
            
            return Response(response_data, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# class AdminNetworkBalanceView(APIView):
#     permission_classes = [permissions.IsAdminUser] 
    
#     def get(self, request):
#         try:
#             # Get all networks
#             networks = Network.objects.all()
            
#             # Initialize response data
#             network_statistics = {}
            
#             for network in networks:
#                 network_statistics[network.name] = {
#                     'network_name': network.name,
#                     'balance': network.balance,  # Balance in network model
#                     'symbol': network.symbol,
#                 }
            
#             # Calculate total balance
#             total_balance = sum(net['balance'] for net in network_statistics.values())
            
#             return Response({
#                 'status': 'success',
#                 'data': {
#                     'network_statistics': network_statistics,
#                     'total_balance': total_balance
#                 },
#                 'message': 'Network statistics retrieved successfully'
#             }, status=status.HTTP_200_OK)
            
#         except Exception as e:
#             return Response({
#                 'status': 'error',
#                 'message': str(e)
#             }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class AdminNetworkBalanceView(APIView):
    permission_classes = [permissions.IsAdminUser] 
    
    def get(self, request):
        try:
            networks = Network.objects.all()
            network_statistics = {}
            
            for network in networks:
                # Calculate total deposits
                total_deposits = Deposit.objects.filter(
                    network=network,
                    status='completed'  # Only count completed deposits
                ).aggregate(
                    total=Sum('amount_usd')
                )['total'] or 0
                
                # Calculate total withdrawals
                total_withdrawals = Withdrawal.objects.filter(
                    network=network,
                    status='completed'  # Only count completed withdrawals
                ).aggregate(
                    total=Sum('amount_usd')
                )['total'] or 0
                
                # Calculate actual balance
                actual_balance = total_deposits - total_withdrawals
                
                network_statistics[network.name] = {
                    'network_name': network.name,
                    'balance': actual_balance,
                    'symbol': network.symbol,
                    'total_deposits': total_deposits,
                    'total_withdrawals': total_withdrawals
                }
            
            # Calculate total balance across all networks
            total_balance = sum(net['balance'] for net in network_statistics.values())
            
            return Response({
                'status': 'success',
                'data': {
                    'network_statistics': network_statistics,
                    'total_balance': total_balance
                },
                'message': 'Network statistics retrieved successfully'
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)