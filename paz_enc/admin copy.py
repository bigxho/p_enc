# admin.py
from django.contrib import admin
from .models import ProfiloSanitario

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