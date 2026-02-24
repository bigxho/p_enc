# admin.py
from django.contrib import admin
from .models import ProfiloSanitario, SecurityLog, DocumentoRiservato
from django.contrib import admin, messages
import hashlib


@admin.register(ProfiloSanitario)
class ProfiloSanitarioAdmin(admin.ModelAdmin):
    # Impedisce la modifica accidentale dall'interfaccia admin
    readonly_fields = ('codice_fiscale',) 
    
    # Opzionale: nascondi del tutto i campi se l'utente non è un superuser
    def get_fields(self, request, obj=None):
        fields = super().get_fields(request, obj)
        if not request.user.is_superuser:
            return [f for f in fields if f != 'codice_fiscale']
        return fields
    
    
@admin.register(SecurityLog)
class SecurityLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'evento', 'utente', 'documento_id', 'indirizzo_ip')
    list_filter = ('evento', 'timestamp')
    readonly_fields = ('timestamp', 'evento', 'utente', 'documento_id', 'indirizzo_ip')
    
    # Impedisce la modifica o eliminazione manuale dei log per integrità
    def has_add_permission(self, request): return False
    def has_change_permission(self, request, obj=None): return False
    
    
@admin.register(DocumentoRiservato)
class DocumentoRiservatoAdmin(admin.ModelAdmin):
    list_display = ('id', 'utente', 'caricato_il', 'download_effettuati', 'file_hash_status')
    actions = ['verifica_integrita_massa']

    def file_hash_status(self, obj):
        # Mostra una spunta verde o una X rossa nella lista
        return "✅ Valido" # Implementazione semplificata per la visualizzazione
    
    @admin.action(description='Verifica integrità dei file selezionati')
    def verifica_integrita_massa(self, request, queryset):
        errori = 0
        successi = 0
        
        for doc in queryset:
            try:
                # Apriamo il file decifrato
                with doc.file_documento.open() as f:
                    sha256_hash = hashlib.sha256()
                    for chunk in f.chunks():
                        sha256_hash.update(chunk)
                    
                    if sha256_hash.hexdigest() == doc.file_hash:
                        successi += 1
                    else:
                        errori += 1
            except Exception:
                errori += 1
        
        if errori > 0:
            self.message_user(request, f"Audit completato: {successi} integri, {errori} CORROTTI!", messages.ERROR)
        else:
            self.message_user(request, f"Audit completato: tutti i {successi} file sono integri.", messages.SUCCESS)
            
            
