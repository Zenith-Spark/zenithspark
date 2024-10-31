from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.core.exceptions import ValidationError
from django.db import transaction
from .models import Deposit, Withdrawal

@receiver(pre_save, sender=Deposit)
def update_network_balance_on_deposit(sender, instance, **kwargs):
    try:
        # Check if this is an existing instance
        if instance.pk:
            old_instance = Deposit.objects.get(pk=instance.pk)
            # Only update balance if status is changing to 'completed'
            if old_instance.status != 'completed' and instance.status == 'completed':
                with transaction.atomic():
                    network = instance.network
                    network.balance += instance.amount_usd
                    network.save()
                    print(f"Network balance updated for deposit {instance.transaction_id}. New balance: {network.balance}")
        # For new instances that are already completed
        elif instance.status == 'completed':
            with transaction.atomic():
                network = instance.network
                network.balance += instance.amount_usd
                network.save()
                print(f"Network balance updated for new deposit {instance.transaction_id}. New balance: {network.balance}")
    except Exception as e:
        raise ValidationError(f"Error updating network balance for deposit: {str(e)}")

@receiver(pre_save, sender=Withdrawal)
def update_network_balance_on_withdrawal(sender, instance, **kwargs):
    try:
        # Check if this is an existing instance
        if instance.pk:
            old_instance = Withdrawal.objects.get(pk=instance.pk)
            # Only update balance if status is changing to 'completed'
            if old_instance.status != 'completed' and instance.status == 'completed':
                with transaction.atomic():
                    network = instance.network
                    if network.balance < instance.amount_usd:
                        raise ValidationError("Insufficient network balance for withdrawal")
                    network.balance -= instance.amount_usd
                    network.save()
                    print(f"Network balance updated for withdrawal {instance.transaction_id}. New balance: {network.balance}")
        # For new instances that are already completed
        elif instance.status == 'completed':
            with transaction.atomic():
                network = instance.network
                if network.balance < instance.amount_usd:
                    raise ValidationError("Insufficient network balance for withdrawal")
                network.balance -= instance.amount_usd
                network.save()
                print(f"Network balance updated for new withdrawal {instance.transaction_id}. New balance: {network.balance}")
    except Exception as e:
        raise ValidationError(f"Error updating network balance for withdrawal: {str(e)}")