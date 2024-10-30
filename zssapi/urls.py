from django.urls import path
from .views import UserRegistration, LoginView, LogoutView, ForgotPasswordView, ChangePassword, UserProfile, InvestmentAPIView, InvestmentPlanListView, InvestmentPlanAdminView, InvestmentAPIView, ReferralView, ApplyReferralCode, AdminReferralView, MyReferralCodeView, UserReferralDetailsView , InvestmentAdminView, NetworkAPIView, DepositAPIView, AdminUpdateDepositStatusAPIView, WithdrawalAPIView, AdminWithdrawalConfirmationView, NotificationAPIView, NetworkTransactionHistoryAPIView, ExchangeRatesAPIView, UpdateNetworkBalanceAPIView, TotalBalanceView


urlpatterns = [
    path('get-referral-info/', ReferralView.as_view(), name='referral-info'),
    path('apply-referral/', ApplyReferralCode.as_view(), name='apply-referral'),
    path('admin/get-referrals/', AdminReferralView.as_view(), name='admin-referrals'),
    path('get-referral-code/', MyReferralCodeView.as_view(), name='my-referral-code'),
    path('get-referral-details/', UserReferralDetailsView.as_view(), name='referral-details'),
    path('register/', UserRegistration.as_view(), name='user-registration'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('change-password/', ChangePassword.as_view(), name='change-password'),
    path('profile/', UserProfile.as_view(), name='user-profile'),
    path('get-plans/', InvestmentPlanListView.as_view(), name='investment-plans'),
    path('create-plans/', InvestmentPlanAdminView.as_view(), name='create-investment-plan'),
    path('update-plans/<int:pk>/', InvestmentPlanAdminView.as_view(), name='update-investment-plan'),
    path('investments/', InvestmentAPIView.as_view(), name='investments'), 
    path('admin/get-investments/', InvestmentAdminView.as_view(), name='admin-investments'),
    path('admin/update-investments/<int:pk>/', InvestmentAdminView.as_view(), name='update-investment'),
    path('networks/', NetworkAPIView.as_view(), name='networks'),
    path('deposits/', DepositAPIView.as_view(), name='deposits'),
    path('admin/deposits/<str:deposit_id>/', AdminUpdateDepositStatusAPIView.as_view(), name='admin-update-deposit'),
    path('withdrawals/', WithdrawalAPIView.as_view(), name='withdrawals'),
    path('admin/withdrawals/<str:withdrawal_id>/', AdminWithdrawalConfirmationView.as_view(), name='admin-confirm-withdrawal'),
    path('notifications/', NotificationAPIView.as_view(), name='notifications'),
    path('notifications/<int:notification_id>/', NotificationAPIView.as_view(), name='notification-detail'),
    path('network-history/<str:network_name>/', NetworkTransactionHistoryAPIView.as_view(), name='network-history'),
    path('exchange-rates/', ExchangeRatesAPIView.as_view(), name='exchange-rates'),
    path('update-network-balance/', UpdateNetworkBalanceAPIView.as_view(), name='update-network-balance'),
    path('total-balance/', TotalBalanceView.as_view(), name='total-balance'),
]



    # GET /api/v1/get-plans/ - List all active investment plans
    # POST /api/v1/create-plans/ - Create new investment plan (admin only)
    # PUT /api/v1/update-plans/<pk>/ - Update existing investment plan (admin only)
    # GET, POST /api/investments/ - List user's investments or create new investment
    # GET /api/admin/get-investments/ - List all investments (admin only)
    # PUT /api/admin/investments/<pk>/update/ - Update investment status (admin only)
