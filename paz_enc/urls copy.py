from django.urls import path
from .views import download_documento

urlpatterns = [
    # Usiamo l'ID del database per richiamare il file, non il nome del file!
    path('download-sicuro/<int:doc_id>/', download_documento, name='download_documento'),
]
