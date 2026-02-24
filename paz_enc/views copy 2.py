from django.http import FileResponse, HttpResponseForbidden
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404
from .models import DocumentoRiservato, SecurityLog
from django.shortcuts import render, redirect
from .forms import DocumentoUploadForm


def get_client_ip(request):
    """Utility per estrarre l'IP dell'utente"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


@login_required
def download_sicuro_view(request, doc_id):
    documento = get_object_or_404(DocumentoRiservato, id=doc_id)
    
    # Controllo 1: Proprietà (Solo il proprietario o lo Staff)
    if documento.utente != request.user and not request.user.is_staff:
        return HttpResponseForbidden("Accesso negato: non sei il proprietario.")

    # Controllo 2: Scadenza Temporale
    if documento.e_scaduto():
        return HttpResponseForbidden("Documento scaduto per motivi di sicurezza (oltre 30 giorni).")

    # Controllo 3: Limite di Download
    if documento.ha_raggiunto_il_limite():
        return HttpResponseForbidden("Limite massimo di download raggiunto.")

    # Se tutto ok: Incrementa contatore e serve il file
    documento.download_effettuati += 1
    documento.save()

    # Apre il file (decifrato automaticamente al volo)
    file_handle = documento.file_documento.open()
    
    # Forziamo un nome file "pulito" per il download
    ext = documento.file_documento.name.split('.')[-1]
    filename_pulito = f"Il_Tuo_Documento_{documento.id}.{ext}"
    
    response = FileResponse(file_handle, content_type='application/octet-stream')
    response['Content-Disposition'] = f'attachment; filename="{filename_pulito}"'
    
    return response


@login_required
def upload_documento_view(request):
    if request.method == 'POST':
        form = DocumentoUploadForm(request.POST, request.FILES)
        if form.is_valid():
            documento = form.save(commit=False)
            documento.utente = request.user  # Colleghiamo l'utente loggato
            documento.save()
            return redirect('lista_documenti')
    else:
        form = DocumentoUploadForm()
    return render(request, 'upload.html', {'form': form})

@login_required
def lista_documenti_view(request):
    # Vediamo solo i documenti dell'utente loggato
    documenti = DocumentoRiservato.objects.filter(utente=request.user)
    return render(request, 'lista.html', {'documenti': documenti})