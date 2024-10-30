from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .models import CustomUser, Network, Deposit, Withdrawal, InvestmentPlan, Investment, Network, CustomUser, Notification, Deposit, Withdrawal
from unittest.mock import patch
from decimal import Decimal

class AuthenticationTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.register_url = reverse('user-registration')
        self.login_url = reverse('login')
        self.user_data = {
            'email_address': 'test@example.com',
            'password': 'Test123!@#',
            'full_name': 'Test User',
            'gender': 'MALE'
        }

    def test_user_registration(self):
        response = self.client.post(self.register_url, self.user_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertEqual(CustomUser.objects.count(), 1)

    def test_user_login(self):
        # Create user first
        user = CustomUser.objects.create_user(
            email_address=self.user_data['email_address'],
            password=self.user_data['password']
        )
        
        # Attempt login
        response = self.client.post(self.login_url, {
            'email_address': self.user_data['email_address'],
            'password': self.user_data['password']
        })
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_login_with_invalid_credentials(self):
        response = self.client.post(self.login_url, {
            'email_address': 'wrong@example.com',
            'password': 'wrongpassword'
        })
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class UserProfileTests(APITestCase):
    def setUp(self):
        self.user = CustomUser .objects.create_user(
            email_address='test@example.com',
            password='Test123!@#'
        )
        self.client = APIClient()
        self.user_profile_url = reverse('user-profile')
        self.client.force_authenticate(user=self.user)

    def test_get_user_profile(self):
        response = self.client.get(self.user_profile_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_update_user_profile(self):
        response = self.client.put(self.user_profile_url, {
            'full_name': 'Updated Test User'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)

class NetworkTests(APITestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email_address='test@example.com',
            password='Test123!@#'
        )
        self.client = APIClient()
        self.network_url = reverse('networks')
        self.client.force_authenticate(user=self.user)
        
        # Create test network
        self.network = Network.objects.create(
            name='Test Network',
            symbol='TEST'
        )

    def test_get_networks(self):
        response = self.client.get(self.network_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['name'], 'Test Network')

class DepositTests(APITestCase):
    def setUp(self):
        # Create test user
        self.user = CustomUser.objects.create_user(
            email_address='test@example.com',
            password='testpass123'
        )
        # Create test network
        self.network = Network.objects.create(
            name='Bitcoin',
            symbol='BTC',
            wallet_address='1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
            balance=Decimal('10.0')
        )
        # Authenticate user
        self.client.force_authenticate(user=self.user)
        # Set up deposit data
        self.deposit_data = {
            'network': self.network.id,
            'amount_usd': '100.00',
            'amount_crypto': '0.005'
        }

    def test_create_deposit(self):
        """Test creating a new deposit"""
        response = self.client.post(reverse('deposits'), self.deposit_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Deposit.objects.count(), 1)
        self.assertEqual(Notification.objects.count(), 1)

    def test_get_user_deposits(self):
        """Test retrieving user deposits"""
        # Create test deposit
        Deposit.objects.create(
            user=self.user,
            network=self.network,
            amount_usd=Decimal('100.00'),
            amount_crypto=Decimal('0.005')
        )
        response = self.client.get(reverse('deposits'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_invalid_deposit_amount(self):
        """Test creating deposit with invalid amount"""
        invalid_data = self.deposit_data.copy()
        invalid_data['amount_usd'] = '-100.00'
        response = self.client.post(reverse('deposits'), invalid_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

class WithdrawalTests(APITestCase):
    def setUp(self):
        # Create test user
        self.user = CustomUser.objects.create_user(
            email_address='test@example.com',
            password='testpass123'
        )
        # Create test network
        self.network = Network.objects.create(
            name='Bitcoin',
            symbol='BTC',
            wallet_address='1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
            balance=Decimal('10.0')
        )
        # Authenticate user
        self.client.force_authenticate(user=self.user)
        # Set up withdrawal data
        self.withdrawal_data = {
            'network': self.network.id,
            'amount_usd': '100.00',
            'amount_crypto': '0.005',
            'wallet_address': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
        }

    def test_create_withdrawal(self):
        """Test creating a new withdrawal"""
        response = self.client.post(reverse('withdrawals'), self.withdrawal_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Withdrawal.objects.count(), 1)
        self.assertEqual(Notification.objects.count(), 1)

    def test_get_user_withdrawals(self):
        """Test retrieving user withdrawals"""
        Withdrawal.objects.create(
            user=self.user,
            network=self.network,
            amount_usd=Decimal('100.00'),
            amount_crypto=Decimal('0.005'),
            wallet_address='1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
        )
        response = self.client.get(reverse('withdrawals'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_invalid_withdrawal_amount(self):
        """Test creating withdrawal with invalid amount"""
        invalid_data = self.withdrawal_data.copy()
        invalid_data['amount_usd'] = '-100.00'
        response = self.client.post(reverse('withdrawals'), invalid_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

class AdminDepositTests(APITestCase):
    def setUp(self):
        # Create test admin user
        self.admin = CustomUser.objects.create_user(
            email_address='admin@example.com',
            password='adminpass123',
            is_staff=True
        )
        # Authenticate admin
        self.client.force_authenticate(user=self.admin)
        # Create test deposit
        self.deposit = Deposit.objects.create(
            user=CustomUser .objects.create_user(
                email_address='user@example.com',
                password='userpass123'
            ),
            network=Network.objects.create(
                name='Bitcoin',
                symbol='BTC',
                wallet_address='1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
                balance=Decimal('10.0')
            ),
            amount_usd=Decimal('100.00'),
            amount_crypto=Decimal('0.005')
        )

    def test_update_deposit_status(self):
        """Test updating deposit status as admin"""
        response = self.client.patch(reverse('admin-update-deposit', args=[self.deposit.transaction_id]), {'status': 'completed'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(Deposit.objects.get(transaction_id=self.deposit.transaction_id).status, 'completed')
        self.assertEqual(Notification.objects.count(), 1)

class AdminWithdrawalTests(APITestCase):
    def setUp(self):
        # Create test admin user
        self.admin = CustomUser.objects.create_user(
            email_address='admin@example.com',
            password='adminpass123',
            is_staff=True
        )
        # Authenticate admin
        self.client.force_authenticate(user=self.admin)
        # Create test withdrawal
        self.withdrawal = Withdrawal.objects.create(
            user=CustomUser.objects.create_user(
                email_address='user@example.com',
                password='userpass123'
            ),
            network=Network.objects.create(
                name='Bitcoin',
                symbol='BTC',
                wallet_address='1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
                balance=Decimal('10.0')
            ),
            amount_usd=Decimal('100.00'),
            amount_crypto=Decimal('0.005'),
            wallet_address='1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
        )

    def test_update_withdrawal_status(self):
        """Test updating withdrawal status as admin"""
        response = self.client.post(reverse('admin-confirm-withdrawal', args=[self.withdrawal.transaction_id]), {'status': 'completed'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(Withdrawal.objects.get(transaction_id=self.withdrawal.transaction_id).status, 'completed')
        self.assertEqual(Notification.objects.count(), 1)

class InvestmentPlanTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = CustomUser.objects.create_user(
            email_address='test@example.com',
            password='Test123!@#'
        )
        self.admin_user = CustomUser.objects.create_superuser(
            email_address='admin@example.com',
            password='Admin123!@#'
        )
        
        self.plan = InvestmentPlan.objects.create(
            name='Test Plan',
            minimum_amount=100,
            maximum_amount=1000,
            profit_percentage=10,
            duration_days=30,
            is_active=True
        )

    def test_list_investment_plans(self):
        response = self.client.get(reverse('investment-plans'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_create_investment_plan_as_admin(self):
        self.client.force_authenticate(user=self.admin_user)
        data = {
            'name': 'New Plan',
            'minimum_amount': 200,
            'maximum_amount': 2000,
            'profit_percentage': 15,
            'duration_days': 60,
            'is_active': True
        }
        response = self.client.post(reverse('create-investment-plan'), data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

class InvestmentTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = CustomUser.objects.create_user(
            email_address='test@example.com',
            password='Test123!@#'
        )
        self.client.force_authenticate(user=self.user)
        
        self.plan = InvestmentPlan.objects.create(
            name='Test Plan',
            minimum_amount=100,
            maximum_amount=1000,
            profit_percentage=10,
            duration_days=30,
            is_active=True
        )

    def test_create_investment(self):
        data = {
            'investment_plan': self.plan.id,
            'amount': 500
        }
        response = self.client.post(reverse('investments'), data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(Notification.objects.filter(user=self.user).exists())

    def test_list_user_investments(self):
        Investment.objects.create(
            user=self.user,
            investment_plan=self.plan,
            amount=500,
            expected_profit=50,
            return_time=timezone.now() + timezone.timedelta(days=30)
        )
        response = self.client.get(reverse('investments'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

class NotificationTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = CustomUser.objects.create_user(
            email_address='test@example.com',
            password='Test123!@#'
        )
        self.client.force_authenticate(user=self.user)
        
        self.notification = Notification.objects.create(
            user=self.user,
            message='Test notification',
            is_read=False
        )

    def test_list_notifications(self): 
        response = self.client.get(reverse('notifications'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_mark_notification_as_read(self):
        response = self.client.put(reverse('notification-detail', args=[self.notification.id]))
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.notification.refresh_from_db()
        self.assertTrue(self.notification.is_read)

class NetworkTransactionHistoryTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = CustomUser.objects.create_user(
            email_address='test@example.com',
            password='Test123!@#'
        )
        self.client.force_authenticate(user=self.user)
        
        self.network = Network.objects.create(
            name='Test Network',
            symbol='TEST',
            balance=1000
        )
        
        self.deposit = Deposit.objects.create(
            user=self.user,
            network=self.network,
            amount_usd=100,
            status='completed'
        )
        
        self.withdrawal = Withdrawal.objects.create(
            user=self.user,
            network=self.network,
            amount_usd=50,
            amount_crypto=120,
            status='completed'
        )

    def test_network_transaction_history(self):
        response = self.client.get(reverse('network-history', args=[self.network.name]))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['deposits']), 1)
        self.assertEqual(len(response.data['withdrawals']), 1)

class ExchangeRatesTests(APITestCase):
    def setUp(self):
        # self.client = APIClient()
        self.user = CustomUser.objects.create_user(
            email_address='test@example.com',
            password='Test123!@#'
        )
        self.network = Network.objects.create(
            name='Bitcoin',
            symbol='BTC',
            wallet_address='1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
            balance=Decimal('10.0')
        )
        self.client.force_authenticate(user=self.user)
        
    def test_exchange_rates(self):
        response = self.client.get(reverse('exchange-rates'), {
            'amount_usd': '100',
            'network': 'Bitcoin'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('amount_crypto', response.data)
        self.assertIn('exchange_rate', response.data)
    
    def test_exchange_rates_missing_params(self):
        """Test exchange rates API with missing query parameters"""
        # Make a request without query parameters
        response = self.client.get(reverse('exchange-rates'))
        # Expect a 400 Bad Request due to missing params
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_exchange_rates_invalid_amount(self):
        """Test exchange rates API with invalid amount_usd"""
        # Provide an invalid amount_usd (non-numeric)
        response = self.client.get(reverse('exchange-rates'), {
            'amount_usd': 'invalid_amount',
            'network': 'Bitcoin'
        })
        # Expect a 400 Bad Request due to invalid amount
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    

class UpdateNetworkBalanceTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = CustomUser.objects.create_user(
            email_address='test@example.com',
            password='Test123!@#'
        )
        self.client.force_authenticate(user=self.user)
        
        self.network = Network.objects.create(
            name='Test Network',
            symbol='TEST',
            balance=1000
        )
        
        self.deposit = Deposit.objects.create(
            user=self.user,
            network=self.network,
            amount_usd=100,
            status='completed'
        )
        
        self.withdrawal = Withdrawal.objects.create(
            user=self.user,
            network=self.network,
            amount_usd=50,
            status='completed'
        )

    def test_update_network_balance(self):

        response = self.client.post(reverse('update-network-balance'), {'transaction_id': self.deposit.transaction_id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.network.refresh_from_db()
        self.assertEqual(self.network.balance, 1100)

class TotalBalanceViewTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = CustomUser.objects.create_user(
            email_address='test@example.com',
            password='Test123!@#'
        )
        self.client.force_authenticate(user=self.user)
        
        self.network1 = Network.objects.create(
            name='Test Network 1',
            symbol='TEST1',
            balance=1000
        )
        
        self.network2 = Network.objects.create(
            name='Test Network 2',
            symbol='TEST2',
            balance=2000
        )

    def test_total_balance(self):
        response = self.client.get(reverse('total-balance'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['total_balance'], 3000)

class ReferralTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        # Create a referrer user
        self.referrer = CustomUser.objects.create_user(
            email_address='referrer@example.com',
            password='Test123!@#',
            full_name='Referrer User',
            referral_code='REF123'
        )
        
        # Create a regular user
        self.user = CustomUser.objects.create_user(
            email_address='user@example.com',
            password='Test123!@#',
            full_name='Test User',
            referral_code='USER123'
        )
        
        # Create an admin user
        self.admin_user = CustomUser.objects.create_superuser(
            email_address='admin@example.com',
            password='Admin123!@#',
            full_name='Admin User'
        )

    def test_get_referral_info(self):
        """Test getting user's referral information"""
        self.client.force_authenticate(user=self.user)
        response = self.client.get(reverse('referral-info'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('referral_code', response.data)

    def test_apply_referral_code_success(self):
        """Test successfully applying a referral code"""
        self.client.force_authenticate(user=self.user)
        response = self.client.post(reverse('apply-referral'), {
            'referral_code': self.referrer.referral_code
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertEqual(self.user.referred_by, self.referrer)
        
        # Check if notification was created
        self.assertTrue(
            Notification.objects.filter(
                user=self.referrer,
                message__contains=self.user.full_name
            ).exists()
        )

    def test_apply_referral_code_already_referred(self):
        """Test applying referral code when user is already referred"""
        self.client.force_authenticate(user=self.user)
        self.user.referred_by = self.referrer
        self.user.save()
        
        response = self.client.post(reverse('apply-referral'), {
            'referral_code': 'ANOTHER123'
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('already used', response.data['error'])

    def test_apply_own_referral_code(self):
        """Test applying own referral code"""
        self.client.force_authenticate(user=self.user)
        response = self.client.post(reverse('apply-referral'), {
            'referral_code': self.user.referral_code
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('cannot use your own', response.data['error'])

    def test_apply_invalid_referral_code(self):
        """Test applying invalid referral code"""
        self.client.force_authenticate(user=self.user)
        response = self.client.post(reverse('apply-referral'), {
            'referral_code': 'INVALID123'
        })
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

class AdminReferralTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.admin_user = CustomUser.objects.create_superuser(
            email_address='admin@example.com',
            password='Admin123!@#'
        )
        self.referrer = CustomUser.objects .create_user(
            email_address='referrer@example.com',
            password='Test123!@#',
            full_name='Referrer User',
            referral_code='REF123'
        )
        self.referred_user = CustomUser.objects.create_user(
            email_address='referred@example.com',
            password='Test123!@#',
            full_name='Referred User',
            referred_by=self.referrer
        )

    def test_admin_referral_view(self):
        """Test admin referral view"""
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.get(reverse('admin-referrals'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

class MyReferralCodeTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = CustomUser.objects.create_user(
            email_address='user@example.com',
            password='Test123!@#',
            full_name='Test User',
            referral_code='USER123'
        )

    def test_my_referral_code(self):
        """Test getting own referral code"""
        self.client.force_authenticate(user=self.user)
        response = self.client.get(reverse('my-referral-code'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('referral_code', response.data)
        self.assertEqual(response.data['referral_code'], self.user.referral_code)

class UserReferralDetailsTests(APITestCase):
    def setUp(self):
        # self.client = APIClient()
        self.referrer = CustomUser.objects.create_user(
            email_address='referrer@example.com',
            password='Test123!@#',
            full_name='Referrer User',
            referral_code='REF123'
        )
        self.referred_user1 = CustomUser.objects.create_user(
            email_address='referred1@example.com',
            password='Test123!@#',
            full_name='Referred User 1',
            referred_by=self.referrer
        )
        self.referred_user2 = CustomUser .objects.create_user(
            email_address='referred2@example.com',
            password='Test123!@#',
            full_name='Referred User 2',
            referred_by=self.referrer
        )

    def test_user_referral_details(self):
        """Test getting detailed information about referred users"""
        self.client.force_authenticate(user=self.referrer)
        response = self.client.get(reverse('referral-details'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

class InvestmentTests(APITestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email_address='test@example.com',
            password='Test123!@#'
        )
        self.plan = InvestmentPlan.objects.create(
            name='Test Plan',
            profit_percentage=Decimal('10.00'),
            duration_days=30,
            minimum_amount=Decimal('100.00'),
            maximum_amount=Decimal('1000.00'),
            is_active=True
        )
        self.client.force_authenticate(user=self.user)
    def test_create_investment(self):
        self.client.force_authenticate(user=self.user)
        data = {
            'investment_plan': self.plan.id,
            'amount': 500,
            'payment_method': 'bitcoin',  
            'status': 'pending'
        }
        response = self.client.post(reverse('investments'), data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

class InvestmentPlanTests(APITestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email_address='test@example.com',
            password='Test123!@#'
        )
        self.client.force_authenticate(user=self.user)

    def test_list_investment_plans(self):
        self.client.force_authenticate(user=self.user)  # Add authentication
        response = self.client.get(reverse('investment-plans'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

class LogoutTests(APITestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email_address='test@example.com',
            password='Test123!@#'
        )
        self.client = APIClient()
        self.logout_url = reverse('logout')
        self.refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(self.refresh.access_token)}')

    def test_logout_success(self):
        """Test logout with valid refresh token"""
        response = self.client.post(self.logout_url, {'refresh_token': str(self.refresh)})
        self.assertEqual(response.status_code, status.HTTP_205_RESET_CONTENT)

    def test_logout_without_refresh_token(self):
        """Test logout without providing refresh token"""
        response = self.client.post(self.logout_url, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class PasswordManagementTests(APITestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email_address='test@example.com',
            password='Test123!@#'
        )
        self.client = APIClient()
        self.forgot_password_url = reverse('forgot-password')
        self.change_password_url = reverse('change-password')

    def test_forgot_password(self):
        response = self.client.post(reverse('forgot-password'), {'email_address': 'test@example.com'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_change_password(self):
        # Authenticate the user first
        self.client.force_authenticate(user=self.user)
        response = self.client.post(reverse('change-password'), {
            'old_password': 'Test123!@#',
            'new_password': 'NewPassword123!@#'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)