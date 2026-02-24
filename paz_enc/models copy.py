from django.db import models
from django_cryptography.fields import encrypted
from django.db import models
from django_encrypted_filefield import EncryptedFileField
import os
import uuid
from django.db.models.signals import post_delete
from django.dispatch import receiver


class ProfiloSanitario(models.Model):
    utente = models.OneToOneField('auth.User', on_delete=models.CASCADE)
    
    # Questo dato sarà cifrato nel database (AES-256)
    codice_fiscale = encrypted(models.CharField(max_length=16))
    
    # Anche i file possono essere protetti o i testi lunghi
    diagnosi_riservata = encrypted(models.TextField())
    
    data_creazione = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Dati sensibili di {self.utente.username}"
    
    
class DocumentoUtente(models.Model):
    utente = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    tipo_documento = models.CharField(max_length=50)
    
    # Il file verrà salvato criptato (AES-256)
    file_scansionato = EncryptedFileField(upload_to='documenti_riservati/%Y/%m/%d/')
    
    caricato_il = models.DateTimeField(auto_now_add=True)
    

def secure_rename(instance, filename):
    """
    Rinomina il file usando un UUID e mantiene l'estensione originale.
    """
    ext = filename.split('.')[-1]
    # Genera un nome file casuale (es: 550e8400-e29b-41d4-a716-446655440000)
    filename = f"{uuid.uuid4()}.{ext}"
    
    # Organizza i file in sottocartelle per anno/mese/giorno per evitare 
    # di avere migliaia di file in una singola cartella (ottimizzazione OS)
    return os.path.join('documenti_riservati/%Y/%m/%d/', filename)


class DocumentoRiservato(models.Model):
    utente = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    
    # Usiamo la funzione secure_rename per il parametro upload_to
    file_documento = EncryptedFileField(
        upload_to=secure_rename,
        # Aggiungiamo un aiuto extra per la sicurezza
        help_text="Il file verrà rinominato e criptato automaticamente."
    )
    
    caricato_il = models.DateTimeField(auto_now_add=True)

    download_effettuati = models.PositiveIntegerField(default=0)
    limite_massimo_download = models.PositiveIntegerField(default=5) # Esempio: max 5 volte

    def ha_raggiunto_il_limite(self):
        return self.download_effettuati >= self.limite_massimo_download

    def __str__(self):
        return f"Doc_{self.utente.username}_{self.id}"
    
    

@receiver(post_delete, sender=DocumentoRiservato)
def auto_delete_file_on_delete(sender, instance, **kwargs):
    """
    Cancella il file dal filesystem quando il record viene eliminato dal DB.
    """
    if instance.file_documento:
        if os.path.isfile(instance.file_documento.path):
            os.remove(instance.file_documento.path)
            
            

class DocumentoRiservatoDownload(models.Model):
    # ... i campi precedenti ...
    download_effettuati = models.PositiveIntegerField(default=0)
    limite_massimo_download = models.PositiveIntegerField(default=5) # Esempio: max 5 volte

    def ha_raggiunto_il_limite(self):
        return self.download_effettuati >= self.limite_massimo_download