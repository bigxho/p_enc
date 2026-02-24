import uuid, os, hashlib
from django.db import models
from django.utils import timezone
from datetime import timedelta
#from fernet_fields import EncryptedCharField, EncryptedTextField
#from django_cryptography.fields import EncryptedMixin
#import django_cryptography.fields
#from django_encrypted_filefield.fields import EncryptedFileField
#import django_encrypted_filefield.fields
from cryptography.fernet import Fernet

def secure_rename(instance, filename):
    ext = filename.split('.')[-1]
    return f"docs/{timezone.now().strftime('%Y/%m/%d')}/{uuid.uuid4()}.{ext}"

class DocumentoRiservato(models.Model):
    encrypt_cf = django_cryptography.fields.encrypt
    encrypt_fl = django_encrypted_filefield.fields.EncryptedFieldFile
    utente = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    codice_fiscale = encrypt_cf(models.CharField(max_length=16))
    file_documento = encrypt_fl(upload_to=secure_rename)
    
    # Integrità e Controllo
    file_hash = models.CharField(max_length=64, editable=False) 
    caricato_il = models.DateTimeField(auto_now_add=True)
    download_effettuati = models.PositiveIntegerField(default=0)
    limite_download = models.PositiveIntegerField(default=5)

    def e_scaduto(self):
        return timezone.now() > self.caricato_il + timedelta(days=30)

    def calcola_hash_corrente(self):
        """Calcola l'hash SHA-256 del file decifrato."""
        sha256 = hashlib.sha256()
        with self.file_documento.open() as f:
            for chunk in f.chunks():
                sha256.update(chunk)
        return sha256.hexdigest()


class SecurityLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    utente = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True)
    evento = models.CharField(max_length=50)
    ip = models.GenericIPAddressField()
    doc_id = models.IntegerField(null=True)