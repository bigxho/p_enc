import os
import uuid
import hashlib
from django.db import models
from django.utils import timezone
from datetime import timedelta
from django.dispatch import receiver
from django.db.models.signals import post_delete

# Import per la sicurezza
from django_cryptography.fields import encrypted
from django_encrypted_filefield.fields import EncryptedFileField



class ProfiloSanitario(models.Model):
    utente = models.OneToOneField('auth.User', on_delete=models.CASCADE)
    
    # Questo dato sarà cifrato nel database (AES-256)
    codice_fiscale = encrypted(models.CharField(max_length=16))
    
    # Anche i file possono essere protetti o i testi lunghi
    diagnosi_riservata = encrypted(models.TextField())
    
    data_creazione = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Dati sensibili di {self.utente.username}"
    

def secure_rename(instance, filename):
    """Genera un percorso sicuro: documenti/anno/mese/giorno/UUID.estensione"""
    ext = filename.split('.')[-1]
    nome_uuid = f"{uuid.uuid4()}.{ext}"
    path = timezone.now().strftime('documenti_riservati/%Y/%m/%d/')
    return os.path.join(path, nome_uuid)


class DocumentoRiservato(models.Model):
    # Relazione con l'utente
    utente = models.ForeignKey('auth.User', on_delete=models.CASCADE, related_name='documenti')
    
    # 1. TESTO CRIPTATO (es. Codice Fiscale) nel Database
    codice_fiscale = encrypted(models.CharField(max_length=16, help_text="Cifrato nel DB"))
    
    # 2. FILE CRIPTATO sul disco e RINOMINATO con UUID
    file_documento = EncryptedFileField(
        upload_to=secure_rename, 
        help_text="Cifrato sul disco e URL non indovinabile"
    )
    
    # 3. METADATI DI CONTROLLO
    caricato_il = models.DateTimeField(auto_now_add=True)
    download_effettuati = models.PositiveIntegerField(default=0)
    limite_massimo_download = models.PositiveIntegerField(default=5)

    class Meta:
        verbose_name = "Documento Riservato"
        verbose_name_plural = "Documenti Riservati"

    def __str__(self):
        return f"Doc_{self.id} - {self.utente.username}"

    # Metodi di utility per la sicurezza
    def ha_raggiunto_il_limite(self):
        return self.download_effettuati >= self.limite_massimo_download

    def e_scaduto(self):
        """Verifica se il documento ha più di 30 giorni"""
        return timezone.now() > self.caricato_il + timedelta(days=30)
    
    # ... campi precedenti ...
    file_hash = models.CharField(max_length=64, editable=False) # Hash SHA-256

    def calcola_hash(self, file_field):
        sha256_hash = hashlib.sha256()
        # Leggiamo il file a pezzi (chunks) per non intasare la RAM con file grandi
        for chunk in file_field.chunks():
            sha256_hash.update(chunk)
        return sha256_hash.hexdigest()


class DocumentoUtente(models.Model):
    utente = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    tipo_documento = models.CharField(max_length=50)
    
    # Il file verrà salvato criptato (AES-256)
    file_scansionato = EncryptedFileField(upload_to='documenti_riservati/%Y/%m/%d/')
    
    caricato_il = models.DateTimeField(auto_now_add=True)
    

# 4. PULIZIA AUTOMATICA (Signal)
# Quando cancelli il record dal DB, cancella anche il file fisico (criptato) dal disco
@receiver(post_delete, sender=DocumentoRiservato)
def auto_delete_file_on_delete(sender, instance, **kwargs):
    if instance.file_documento:
        if os.path.isfile(instance.file_documento.path):
            os.remove(instance.file_documento.path)
            
            
# models.py
class SecurityLog(models.Model):
    EVENTO_CHOICES = [
        ('DOWNLOAD_OK', 'Download Riuscito'),
        ('ACCESSO_NEGATO', 'Tentativo di Accesso Non Autorizzato'),
        ('LIMITE_RAGGIUNTO', 'Limite Download Superato'),
        ('SCADUTO', 'Tentativo Accesso File Scaduto'),
    ]

    utente = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True)
    documento_id = models.IntegerField(null=True)
    evento = models.CharField(max_length=20, choices=EVENTO_CHOICES)
    indirizzo_ip = models.GenericIPAddressField(null=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.timestamp} - {self.evento} - Utente: {self.utente}"