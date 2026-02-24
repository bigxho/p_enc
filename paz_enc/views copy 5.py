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
from django.core.cache import cache


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

#************************************************************************************
@login_required
def download_sicuro(request, doc_id):
    """
    Gestisce il download protetto:
    1. Verifica proprietà e permessi.
    2. Controllo Throttling tramite Redis (Cross-Server).
    3. Decriptazione AES-256 (Fernet) al volo.
    4. Consegna del file senza esporre il percorso reale.
    """
    # 1. Recupero documento e controllo proprietà
    doc = get_object_or_404(DocumentoRiservato, id=doc_id, utente=request.user)

    # 2. Controllo Limiti Download con Redis (Atomic Counter)
    # Chiave univoca per utente e documento per evitare abusi
    cache_key = f"dl_limit_{request.user.id}_{doc.id}"
    
    # Incrementiamo il valore in Redis e otteniamo il nuovo conteggio
    # Se la chiave non esiste, parte da 1
    download_count = cache.get(cache_key, 0)

    if download_count >= doc.limite_download:
        return HttpResponseForbidden(
            "Accesso Negato: Hai raggiunto il limite massimo di download per questo file."
        )

    # 3. Decriptazione in Memoria
    try:
        # Recuperiamo la chiave dal file .env
        fernet_key = os.getenv('FERNET_KEY')
        if not fernet_key:
            raise ValueError("Chiave di cifratura mancante!")
        
        f = Fernet(fernet_key.encode())

        # Leggiamo il file criptato dallo Storage (Server B / S3 / Local)
        encrypted_content = doc.file_documento.read()
        
        # Operazione di decriptazione
        decrypted_content = f.decrypt(encrypted_content)

    except Exception as e:
        # In caso di errore (chiave errata, file corrotto), logghiamo e blocchiamo
        return HttpResponseForbidden("Errore critico durante la decriptazione del file.")

    # 4. Aggiornamento Contatori (Database e Redis)
    # Incrementiamo Redis solo DOPO il successo della decriptazione
    cache.set(cache_key, download_count + 1, timeout=86400) # Scade dopo 24h
    
    doc.download_effettuati += 1
    doc.save()

    # 5. Risposta HTTP con il file decriptato
    # Usiamo 'application/octet-stream' per forzare il download di qualsiasi tipo di file
    response = HttpResponse(decrypted_content, content_type='application/octet-stream')
    
    # Puliamo il nome del file per l'header (rimuovendo il percorso del server)
    filename = os.path.basename(doc.file_documento.name)
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    return response
#************************************************************************************


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


