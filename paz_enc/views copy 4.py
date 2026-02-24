import os
from django.shortcuts import render, redirect, get_object_or_404
from django.http import FileResponse, HttpResponseForbidden, HttpResponse
from django.contrib.auth.decorators import login_required
from .models import DocumentoRiservato, SecurityLog
from .forms import DocumentoUploadForm
import hashlib
from django_ratelimit.decorators import ratelimit
from django.contrib.auth.views import LoginView
from django.utils.decorators import method_decorator
from cryptography.fernet import Fernet


def get_client_ip(request):
    """Utility per estrarre l'IP dell'utente"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


@login_required
def upload_view(request):
    if request.method == 'POST':
        form = DocumentoUploadForm(request.POST, request.FILES)
        if form.is_valid():
            doc = form.save(commit=False)
            doc.utente = request.user
            
            # Calcolo hash prima del salvataggio definitivo
            sha = hashlib.sha256()
            for chunk in request.FILES['file_documento'].chunks():
                sha.update(chunk)
            doc.file_hash = sha.hexdigest()
            
            doc.save()
            return redirect('lista_documenti')
    return render(request, 'paz_enc/upload_file.html', {'form': DocumentoUploadForm()})

@login_required
def download_sicuro(request, doc_id):
    doc = get_object_or_404(DocumentoRiservato, id=doc_id)
    ip = request.META.get('REMOTE_ADDR')

    # 1. Controlli Accesso
    if doc.utente != request.user and not request.user.is_staff:
        SecurityLog.objects.create(utente=request.user, evento="NEGATO", ip=ip, doc_id=doc_id)
        return HttpResponseForbidden("Accesso negato.")

    # 2. Controllo Integrità SHA-256
    if doc.calcola_hash_corrente() != doc.file_hash:
        SecurityLog.objects.create(utente=request.user, evento="CORRUZIONE_FILE", ip=ip, doc_id=doc_id)
        return HttpResponseForbidden("Errore: Integrità file compromessa!")

    # 3. Successo
    doc.download_effettuati += 1
    doc.save()
    SecurityLog.objects.create(utente=request.user, evento="DOWNLOAD_OK", ip=ip, doc_id=doc_id)
    
    return FileResponse(doc.file_documento.open(), as_attachment=True, filename=f"Documento_{doc.id}.pdf")


class SafeLoginView(LoginView):
    template_name = 'registration/login.html'

    # 'ip' usa l'indirizzo del client
    # '5/5m' significa 5 richieste ogni 5 minuti
    # 'block=True' lancia un'eccezione Ratelimited se superato
    @method_decorator(ratelimit(key='ip', rate='5/5m', method='POST', block=True))
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)
    
def download_file(request, doc_id):
    doc = get_object_or_404(DocumentoRiservato, id=doc_id, utente=request.user)
    
    # Verifica limite download
    if doc.download_effettuati >= doc.limite_download:
        return HttpResponseForbidden("Limite raggiunto.")

    # Decriptazione al volo
    f = Fernet(os.getenv('FERNET_KEY').encode())
    encrypted_data = doc.file_documento.read()
    decrypted_data = f.decrypt(encrypted_data)

    # Incrementa contatore
    doc.download_effettuati += 1
    doc.save()

    response = HttpResponse(decrypted_data, content_type='application/pdf') # o il tipo corretto
    response['Content-Disposition'] = f'attachment; filename="documento_sicuro.pdf"'
    return response


@login_required
def lista_view(request):
    # Vediamo solo i documenti dell'utente loggato
    documenti = DocumentoRiservato.objects.filter(utente=request.user)
    return render(request, 'paz_enc/list_file.html', {'documenti': documenti})


    
    
"""
from mfa.models import UserKeys

@login_required
def dashboard_sicurezza(request):
    # Recuperiamo tutte le chiavi WebAuthn registrate dall'utente
    chiavi_biometriche = UserKeys.objects.filter(username=request.user.username, key_type="WebAuthn")
    
    context = {
        'chiavi': chiavi_biometriche,
        'documenti_recenti': DocumentoRiservato.objects.filter(utente=request.user).order_by('-caricato_il')[:5]
    }
    return render(request, 'dashboard_sicurezza.html', context)

"""


