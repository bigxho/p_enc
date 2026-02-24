# admin.py
from django.contrib import admin
from .models import ProfiloSanitario, SecurityLog

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