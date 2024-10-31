from django.apps import AppConfig


class ZssapiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'zssapi'

    def ready(self):
        from zssapi import signals