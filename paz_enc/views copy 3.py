from django.http import FileResponse, HttpResponseForbidden
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404
from .models import DocumentoRiservato, SecurityLog
from django.shortcuts import render, redirect
from .forms import DocumentoUploadForm
import hashlib

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
    ip_attuale = get_client_ip(request)
    
    # 1. Controllo Proprietà
    if documento.utente != request.user and not request.user.is_staff:
        SecurityLog.objects.create(
            utente=request.user, documento_id=doc_id, 
            evento='ACCESSO_NEGATO', indirizzo_ip=ip_attuale
        )
        return HttpResponseForbidden("Accesso negato.")

    # 2. Controllo Scadenza
    if documento.e_scaduto():
        SecurityLog.objects.create(
            utente=request.user, documento_id=doc_id, 
            evento='SCADUTO', indirizzo_ip=ip_attuale
        )
        return HttpResponseForbidden("File scaduto.")

    # 3. Controllo Limite
    if documento.ha_raggiunto_il_limite():
        SecurityLog.objects.create(
            utente=request.user, documento_id=doc_id, 
            evento='LIMITE_RAGGIUNTO', indirizzo_ip=ip_attuale
        )
        return HttpResponseForbidden("Limite raggiunto.")

    # DOWNLOAD RIUSCITO
    documento.download_effettuati += 1
    documento.save()
    
    SecurityLog.objects.create(
        utente=request.user, documento_id=doc_id, 
        evento='DOWNLOAD_OK', indirizzo_ip=ip_attuale
    )

    file_handle = documento.file_documento.open()
    response = FileResponse(file_handle, content_type='application/octet-stream')
    response['Content-Disposition'] = f'attachment; filename="Documento_{doc_id}.pdf"'
    return response


@login_required
def upload_documento_view(request):
    if request.method == 'POST':
        form = DocumentoUploadForm(request.POST, request.FILES)
        if form.is_valid():
            documento = form.save(commit=False)
            documento.utente = request.user  # Colleghiamo l'utente loggato
            
            # Calcolo hash dell'originale
            documento.file_hash = documento.calcola_hash(request.FILES['file_documento'])
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



@login_required
def download_sicuro(request, doc_id):
    doc = get_object_or_404(DocumentoRiservato, id=doc_id)
    ip = request.META.get('REMOTE_ADDR')

    # Controlli
    errore = None
    if doc.utente != request.user and not request.user.is_staff: errore = "ACCESSO_NEGATO"
    elif doc.e_scaduto(): errore = "SCADUTO"
    elif doc.download_effettuati >= doc.limite_download: errore = "LIMITE_RAGGIUNTO"

    if errore:
        SecurityLog.objects.create(utente=request.user, evento=errore, ip=ip, doc_id=doc_id)
        return HttpResponseForbidden(f"Errore: {errore}")

    # Successo
    doc.download_effettuati += 1
    
    #**************
    # Recuperiamo il file decifrato
    file_handle = doc.file_documento.open()
    
    # Ricalcoliamo l'hash del file che stiamo per servire
    sha256_hash = hashlib.sha256()
    for chunk in file_handle.chunks():
        sha256_hash.update(chunk)
    current_hash = sha256_hash.hexdigest()

    # CONFRONTO INTEGRITÀ
    if current_hash != doc.file_hash:
        SecurityLog.objects.create(
            utente=request.user, 
            evento="ERRORE_INTEGRITA_FILE", 
            ip=request.META.get('REMOTE_ADDR'), 
            doc_id=doc_id
        )
        return HttpResponseForbidden("Errore critico: l'integrità del file è compromessa. Contatta l'amministratore.")

    # Se l'hash è identico, serviamo il file
    doc.save()
    file_handle.seek(0) # Reset puntatore file dopo la lettura per l'hash
    #doc.save()
    return FileResponse(file_handle, as_attachment=True, filename=f"Doc_{doc.id}.pdf")
    #**************
    
    #doc.save()
    #SecurityLog.objects.create(utente=request.user, evento="DOWNLOAD_OK", ip=ip, doc_id=doc_id)
    #return FileResponse(doc.file_documento.open(), as_attachment=True, filename=f"Doc_{doc.id}.pdf")

#************************************************************************

@login_required
def upload_view(request):
    if request.method == 'POST':
        form = DocumentoUploadForm(request.POST, request.FILES)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.utente = request.user
            
            # Calcolo hash dell'originale
            obj.file_hash = obj.calcola_hash(request.FILES['file_documento'])
            obj.save()
            return redirect('lista')
    return render(request, 'upload.html', {'form': DocumentoUploadForm()})

