# from django.apps import AppConfig

# class ObeeomaappConfig(AppConfig):
#     default_auto_field = 'django.db.models.BigAutoField'
#     name = 'obeeomaapp'

#     # def ready(self):
#     #     from obeeomaapp import signals

from django.apps import AppConfig

class ObeeomaappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'obeeomaapp'
    
    # def ready(self):
        # Import signals here to avoid circular imports
        # import obeeomaapp.signals
from django.apps import AppConfig


class ObeeomaappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'obeeomaapp'
