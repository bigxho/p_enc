from django.shortcuts import render
from django.http import FileResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404
from .models import DocumentoUtente, DocumentoRiservato
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from datetime import timedelta


@login_required # Solo utenti loggati
def scarica_documento_sicuro(request, doc_id):
    documento = get_object_or_404(DocumentoUtente, id=doc_id)
    
    # Solo il proprietario o un admin può vedere il file
    if request.user == documento.utente or request.user.is_staff:
        # Il file viene decifrato qui dal campo EncryptedFileField
        response = FileResponse(documento.file_scansionato.file)
        return response
    
    return HttpResponseForbidden("Non hai i permessi per visualizzare questo documento.")



@login_required # Solo utenti loggati
def download_documento(request, doc_id):
    # Recuperiamo il documento o diamo 404
    documento = get_object_or_404(DocumentoRiservato, id=doc_id)
    
    # --- IL CUORE DELLA SICUREZZA ---
    # Controlliamo che chi lo chiede sia il proprietario o un admin
    if documento.utente != request.user and not request.user.is_staff:
        return HttpResponseForbidden("Ehi! Questo documento non ti appartiene. 🛑")

    # Recuperiamo il file (il campo EncryptedFileField lo decifra automaticamente)
    file_handle = documento.file_documento.open()
    
    # Prepariamo la risposta per il browser
    response = FileResponse(file_handle, content_type='application/pdf')
    
    # Diamo al file un nome carino per l'utente, così non vede l'UUID
    nome_umano = f"Documento_{request.user.last_name}.pdf"
    response['Content-Disposition'] = f'attachment; filename="{nome_umano}"'
    
    return response


@login_required
def download_documento(request, doc_id):
    documento = get_object_or_404(DocumentoRiservato, id=doc_id)
    
    # 1. Controllo proprietà (già visto)
    if documento.utente != request.user and not request.user.is_staff:
        return HttpResponseForbidden("Accesso negato.")

    # 2. Controllo limite download
    if documento.ha_raggiunto_il_limite():
        return HttpResponseForbidden("Hai esaurito i download disponibili per questo file. Contatta l'assistenza.")

    # 3. Incremento del contatore
    documento.download_effettuati += 1
    documento.save()

    # 4. Servizio del file
    file_handle = documento.file_documento.open()
    response = FileResponse(file_handle, content_type='application/pdf')
    #nome_umano = f"Documento_{documento.id}.pdf"
    nome_umano = f"Documento_{request.user.last_name}.pdf"
    response['Content-Disposition'] = f'attachment; filename="{nome_umano}"'
    
    return response


def e_scaduto(self):
    giorni_validita = 30 # Il documento scade dopo 30 giorni
    return timezone.now() > self.caricato_il + timedelta(days=giorni_validita)