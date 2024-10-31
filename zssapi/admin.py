from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser , InvestmentPlan, Investment, Notification, Network, Deposit, Withdrawal

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    model = CustomUser  
    
    fieldsets = (
        (None, {"fields": ("email_address", "password")}),
        ("Personal Info", {"fields": ("full_name", "gender", "ip_address", "last_login_ip", "referral_code", "referred_by")}),
        ("Permissions", {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")}),
        ("Important dates", {"fields": ("date_joined",)}),  # Note the comma here to make it a tuple
    )
    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("email_address", "full_name", "password1", "password2"),
        }),
    )
    list_display = ("email_address", "full_name", "is_staff", "is_superuser")
    list_filter = ("is_staff", "is_superuser", "is_active",)
    search_fields = ("email_address", "full_name")
    ordering = ("email_address",)
    readonly_fields = ("date_joined",)  # Note the comma here to make it a tuple

    def save_model(self, request, obj, form, change):
        if not change:
            # New user
            obj.set_password(obj.password)
        super().save_model(request, obj, form, change)

    def has_add_permission(self, request):
        return request.user.is_superuser

    def has_change_permission(self, request, obj=None):
        return request.user.is_superuser

    def has_view_permission(self, request, obj=None):
        return request.user.is_superuser

    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser

    def has_module_permission(self, request):
        return request.user.is_superuser

@admin.register(InvestmentPlan)
class InvestmentPlanAdmin(admin.ModelAdmin):
    list_display = ('name', 'profit_percentage', 'duration_days', 'minimum_amount', 'maximum_amount', 'is_active')
    search_fields = ('name',)
    list_filter = ('is_active',)

@admin.register(Investment)
class InvestmentAdmin(admin.ModelAdmin):
    list_display = ('user', 'investment_plan', 'network', 'amount', 'expected_profit', 'investment_time', 'return_time', 'status')
    search_fields = ('user__email_address', 'investment_plan__name')
    list_filter = ('status', 'investment_time')

@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('user', 'message', 'is_read', 'created_at')
    search_fields = ('user__email_address', 'message')
    list_filter = ('is_read', 'created_at')

@admin.register(Network)
class NetworkAdmin(admin.ModelAdmin):
    list_display = ('name', 'symbol', 'wallet_address', 'balance')
    search_fields = ('name', 'symbol')
    list_filter = ('balance',)

@admin.register(Deposit)
class DepositAdmin(admin.ModelAdmin):
    list_display = ('transaction_id', 'user', 'network', 'amount_usd', 'amount_crypto', 'status', 'created_at', 'updated_at')
    search_fields = ('transaction_id', 'user__email_address', 'network__name')
    list_filter = ('status', 'created_at', 'updated_at')

@admin.register(Withdrawal)
class WithdrawalAdmin(admin.ModelAdmin):
    list_display = ('transaction_id', 'user', 'network', 'amount_usd', 'amount_crypto', 'wallet_address', 'status', 'created_at', 'updated_at')
    search_fields = ('transaction_id', 'user__email_address', 'network__name')
    list_filter = ('status', 'created_at', 'updated_at')