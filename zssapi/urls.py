from django.urls import path
from .views import UserRegistration, LoginView, LogoutView, ForgotPasswordView, ChangePassword, UserProfile, UserCountView, AdminNetworkBalanceView, KYCUploadView, UserKYCStatusView, AdminDashboardUsersDetail, AdminTransactionsHistory, AdminKYCListView, AdminKYCUpdateView, InvestmentAPIView, InvestmentPlanListView, InvestmentPlanAdminView, AdminInvestmentEditView, AdminTransactionEditView, InvestmentAPIView, ReferralView, ApplyReferralCode, AdminReferralView, MyReferralCodeView, UserReferralDetailsView , InvestmentAdminView, Networks, DepositAPIView, AdminUpdateDepositStatusAPIView, WithdrawalAPIView, AdminWithdrawalConfirmationView, NotificationAPIView, NetworkTransactionHistoryAPIView, ExchangeRatesAPIView, NetworkBalanceView, UpdateTransactionStatusView, TotalBalanceView


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
    path('admin/create-plans/', InvestmentPlanAdminView.as_view(), name='create-investment-plan'),
    path('admin/update-plans/<str:investment_plan_name>/', InvestmentPlanAdminView.as_view(), name='update-investment-plan'),
    path('investments/', InvestmentAPIView.as_view(), name='investments'), 
    path('admin/get-investments/', InvestmentAdminView.as_view(), name='admin-investments'),
    path('admin/update-investments/<int:pk>/', InvestmentAdminView.as_view(), name='update-investment'),
    path('networks/', Networks.as_view(), name='networks'),
    path('networks/<str:network_name>/', Networks.as_view(), name='network-detail'),
    path('deposits/', DepositAPIView.as_view(), name='deposits'),
    path('deposits/<str:network_name>/', DepositAPIView.as_view(), name='deposits-network'),
    path('admin/deposits/<str:deposit_id>/', AdminUpdateDepositStatusAPIView.as_view(), name='admin-update-deposit'),
    path('withdrawals/', WithdrawalAPIView.as_view(), name='withdrawals'),
    path('withdrawals/<str:network_name>/', WithdrawalAPIView.as_view()),
    path('admin/withdrawals/<str:withdrawal_id>/', AdminWithdrawalConfirmationView.as_view(), name='admin-confirm-withdrawal'),
    path('notifications/', NotificationAPIView.as_view(), name='notifications'),
    path('notifications/<int:notification_id>/', NotificationAPIView.as_view(), name='notification-detail'),
    path('network-history/<str:network_name>/', NetworkTransactionHistoryAPIView.as_view(), name='network-history'),
    path('exchange-rates/', ExchangeRatesAPIView.as_view(), name='exchange-rates'),
    path('network-balances/', NetworkBalanceView.as_view(), name='network-balances'),
    path('network-balance/<str:network_name>/', NetworkBalanceView.as_view(), name='network-balance'),
    path('update-transaction-status/', UpdateTransactionStatusView.as_view(), name='update-transaction-status'),
    path('total-balance/', TotalBalanceView.as_view(), name='total-balance'),
    path('admin/users-detail/', AdminDashboardUsersDetail.as_view(), name='admin-dashboard'),
    path('admin/history/', AdminTransactionsHistory.as_view(), name='admin-transactions'),
    path('admin/investment/<int:investment_id>/edit/', AdminInvestmentEditView.as_view(), name='admin-investment-edit'),
    path('admin/<str:transaction_type>/<int:transaction_id>/edit/', AdminTransactionEditView.as_view(), name='admin-transaction-edit'),
    path('upload-kyc/', KYCUploadView.as_view(), name='upload-kyc'),
    path('user-kyc-status/', UserKYCStatusView.as_view(), name='user-kyc-status'),
    path('admin/kyc-list/', AdminKYCListView.as_view(), name='admin-kyc-list'),
    path('admin/kyc-update/<int:kyc_id>/', AdminKYCUpdateView.as_view(), name='admin-kyc-update'),
    path('admin/users-count/', UserCountView.as_view(), name='user-count'),
    path('admin/network-balances/', AdminNetworkBalanceView.as_view(), name='admin-network-balances'),
]



    # GET /api/v1/get-plans/ - List all active investment plans
    # POST /api/v1/create-plans/ - Create new investment plan (admin only)
    # PUT /api/v1/update-plans/<pk>/ - Update existing investment plan (admin only)
    # GET, POST /api/investments/ - List user's investments or create new investment
    # GET /api/admin/get-investments/ - List all investments (admin only)
    # PUT /api/admin/investments/<pk>/update/ - Update investment status (admin only)
