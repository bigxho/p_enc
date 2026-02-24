#!/bin/bash

# --- CONFIGURAZIONE ---
EMAIL="tua-email@esempio.it"
URL_APP="https://tuodominio.it"
STORAGE_IP="192.168.1.100"
GUNICORN_SOCK="/run/gunicorn.sock"

echo "--- INIZIO MONITORAGGIO FORTEZZA ($(date)) ---"

# 1. Verifica Nginx
if systemctl is-active --quiet nginx; then
    echo "[OK] Nginx è attivo."
else
    echo "[ERRORE] Nginx è DOWN!" | mail -s "ALLERTA: Nginx Down" $EMAIL
fi

# 2. Verifica Gunicorn (Socket)
if [ -S "$GUNICORN_SOCK" ]; then
    echo "[OK] Socket Gunicorn presente."
else
    echo "[ERRORE] Gunicorn non risponde!" | mail -s "ALLERTA: Gunicorn Down" $EMAIL
fi

# 3. Verifica Server Storage (Ping locale)
if ping -c 1 $STORAGE_IP > /dev/null; then
    echo "[OK] Server Storage raggiungibile."
else
    echo "[ERRORE] Server Storage OFF-LINE!" | mail -s "ALLERTA: Storage Down" $EMAIL
fi

# 4. Verifica Risposta Web (HTTP 200)
STATUS=$(curl -o /dev/null -s -w "%{http_code}" $URL_APP)
if [ $STATUS -eq 200 ]; then
    echo "[OK] L'applicazione risponde correttamente (HTTP 200)."
else
    echo "[ERRORE] L'app restituisce errore $STATUS!" | mail -s "ALLERTA: App Errore $STATUS" $EMAIL
fi

echo "--- MONITORAGGIO COMPLETATO ---"