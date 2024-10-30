class DepositTests(APITestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email_address='test@example.com',
            password='Test123!@#'
        )
        self.admin_user = CustomUser.objects.create_superuser(
            email_address='admin@example.com',
            password='Admin123!@#'
        )
        self.client = APIClient()
        self.deposit_url = reverse('deposits')
        self.client.force_authenticate(user=self.user)
        
        self.network = Network.objects.create(
            name='Test Network',
            symbol='TEST'
        )
        
        # Test deposit data
        self.deposit_data = {
            'amount_usd': '100.00',
            'network': self.network.id,
            'wallet_address': '0x123456789'
        }

    def test_create_deposit(self):
        response = self.client.post(self.deposit_url, self.deposit_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('transaction_id', response.data)
        
        # Check if notification was created
        self.assertTrue(Notification.objects.filter(user=self.user).exists())

    def test_get_user_deposits(self):
        # Create a test deposit
        Deposit.objects.create(
            user=self.user,
            amount_usd=Decimal('100.00'),
            network=self.network,
            wallet_address='0x123456789'
        )
        
        response = self.client.get(self.deposit_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

class AdminDepositTests(APITestCase):
    def setUp(self):
        self.admin_user = CustomUser.objects.create_superuser(
            email_address='admin@example.com',
            password='Admin123!@#'
        )
        self.normal_user = CustomUser.objects.create_user(
            email_address='user@example.com',
            password='User123!@#'
        )
        self.client = APIClient()
        self.client.force_authenticate(user=self.admin_user)
        
        self.network = Network.objects.create(
            name='Test Network',
            symbol='TEST'
        )
        
        self.deposit = Deposit.objects.create(
            user=self.normal_user,
            amount_usd=Decimal('100.00'),
            network=self.network,
            wallet_address='0x123456789'
        )
        
        self.update_status_url = reverse('admin-update-deposit', args=[self.deposit.transaction_id])

    def test_update_deposit_status(self):
        response = self.client.patch(self.update_status_url, {'status': 'completed'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data[' status'], 'completed')
        
        # Check if notification was created
        self.assertTrue(Notification.objects.filter(user=self.normal_user).exists())

class WithdrawalTests(APITestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email_address='test@example.com',
            password='Test123!@#'
        )
        self.client = APIClient()
        self.withdrawal_url = reverse('withdrawals')
        self.client.force_authenticate(user=self.user)
        
        self.network = Network.objects.create(
            name='Test Network',
            symbol='TEST'
        )
        
        # Test withdrawal data
        self.withdrawal_data = {
            'amount_usd': '100.00',
            'network': self.network.id,
            'wallet_address': '0x123456789'
        }

    def test_create_withdrawal(self):
        response = self.client.post(self.withdrawal_url, self.withdrawal_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('transaction_id', response.data)
        
        # Check if notification was created
        self.assertTrue(Notification.objects.filter(user=self.user).exists())

    def test_get_user_withdrawals(self):
        # Create a test withdrawal
        Withdrawal.objects.create(
            user=self.user,
            amount_usd=Decimal('100.00'),
            network=self.network,
            wallet_address='0x123456789'
        )
        
        response = self.client.get(self.withdrawal_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

class AdminWithdrawalTests(APITestCase):
    def setUp(self):
        self.admin_user = CustomUser.objects.create_superuser(
            email_address='admin@example.com',
            password='Admin123!@#'
        )
        self.normal_user = CustomUser.objects.create_user(
            email_address='user@example.com',
            password='User123!@#'
        )
        self.client = APIClient()
        self.client.force_authenticate(user=self.admin_user)
        
        self.network = Network.objects.create(
            name='Test Network',
            symbol='TEST'
        )
        
        self.withdrawal = Withdrawal.objects.create(
            user=self.normal_user,
            amount_usd=Decimal('100.00'),
            network=self.network,
            wallet_address='0x123456789'
        )
        
        self.update_status_url = reverse('admin-withdrawal-confirmation', args=[self.withdrawal.transaction_id])

    def test_update_withdrawal_status(self):
        response = self.client.post(self.update_status_url, {'status': 'completed'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'completed')
        
        # Check if notification was created
        self.assertTrue(Notification.objects.filter(user=self.normal_user).exists())
