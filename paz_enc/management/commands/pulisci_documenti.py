# management/commands/pulisci_documenti.py
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from paz_enc.models import DocumentoRiservato

class Command(BaseCommand):
    help = 'Cancella i documenti più vecchi di 30 giorni'

    def handle(self, *args, **options) :
        limite = timezone.now() - timedelta(days=30)
        vecchi_docs = DocumentoRiservato.objects.filter(caricato_il__lt=limite)
        
        conteggio = vecchi_docs.count()
        # Il post_delete signal che abbiamo scritto prima cancellerà i file dal disco automaticamente
        vecchi_docs.delete() 
        
        self.stdout.write(f"Pulizia completata: rimossi {conteggio} documenti.")
        
