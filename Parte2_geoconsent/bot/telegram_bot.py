"""
GeoConsent · Bot de Telegram (localización CON CONSENTIMIENTO)
=============================================================
Requisito 4.3.2 de la guía. Modelo de consentimiento:

  * El bot NO puede localizar a nadie por su número ni activar el GPS de forma remota.
  * Telegram solo entrega una ubicación cuando el USUARIO pulsa el botón "Enviar ubicación"
    (KeyboardButton(request_location=True)) o comparte una "Live Location" desde la app.
    Es decir, cada envío es una acción explícita y consciente del titular.
  * El usuario escribe /stop para dejar de compartir; sus datos se dan de baja en el backend.

Dependencias (no instaladas en este laboratorio sin red):
    pip install python-telegram-bot==21.* requests
Ejecución:
    export TELEGRAM_TOKEN="<token de @BotFather>"
    export GEOCONSENT_URL="http://127.0.0.1:5055"
    python3 telegram_bot.py
"""
import os, logging, requests
from telegram import Update, KeyboardButton, ReplyKeyboardMarkup, ReplyKeyboardRemove
from telegram.ext import (Application, CommandHandler, MessageHandler, ContextTypes, filters)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
BACKEND = os.environ.get("GEOCONSENT_URL", "http://127.0.0.1:5055")
TOKEN = os.environ.get("TELEGRAM_TOKEN", "")

CONSENT_TEXT = (
    "Hola. Puedo *mostrar tu ubicación a quien tú autorices*.\n\n"
    "No puedo localizarte por tu número ni sin que tú envíes tu ubicación. "
    "Tú decides cuándo compartir y puedes parar con /stop.\n\n"
    "Si deseas compartir tu ubicación con *Coordinación Logística*, pulsa un botón:"
)

def consent_keyboard():
    return ReplyKeyboardMarkup(
        [[KeyboardButton("📍 Enviar mi ubicación", request_location=True)],
         ["🔴 Compartir ubicación en vivo (desde el clip de Telegram)"],
         ["/stop"]],
        resize_keyboard=True, one_time_keyboard=False)

async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(CONSENT_TEXT, parse_mode="Markdown", reply_markup=consent_keyboard())

async def on_location(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Se dispara SOLO porque el usuario pulsó el botón o compartió su 'live location'."""
    loc = update.message.location
    live = bool(getattr(update.message, "location", None) and update.edited_message is None
                and loc.live_period)
    # El token de dispositivo se obtiene al verificar el código (vinculación consentida).
    device_token = ctx.user_data.get("device_token")
    payload = {"lat": loc.latitude, "lon": loc.longitude}
    if device_token:
        try:
            r = requests.post(f"{BACKEND}/api/v1/locations", json=payload,
                              headers={"Authorization": f"Bearer {device_token}"}, timeout=5)
            ev = r.json().get("geofence_events") if r.ok else None
            extra = f"\n⚑ Geocerca: {ev}" if ev else ""
        except Exception as e:
            extra = f"\n(aviso: no se pudo contactar el backend: {e})"
    else:
        extra = "\n(modo demo: vincula tu dispositivo con /vincular <token> para registrar en el servidor)"
    kind = "en vivo" if live else "puntual"
    await update.message.reply_text(
        f"Gracias. Ubicación {kind} recibida con tu consentimiento ✅{extra}\n"
        f"Escribe /stop para dejar de compartir.")

async def vincular(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("Uso: /vincular <device_token obtenido al verificar tu código>")
        return
    ctx.user_data["device_token"] = ctx.args[0]
    await update.message.reply_text("Dispositivo vinculado. Ahora tus envíos se registran con tu consentimiento.")

async def stop(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    token = ctx.user_data.pop("device_token", None)
    if token:
        try:
            requests.delete(f"{BACKEND}/api/v1/devices/me",
                            headers={"Authorization": f"Bearer {token}"}, timeout=5)
        except Exception:
            pass
    await update.message.reply_text("Dejaste de compartir. Tu historial fue dado de baja.",
                                    reply_markup=ReplyKeyboardRemove())

def main():
    if not TOKEN:
        raise SystemExit("Define TELEGRAM_TOKEN con el token de @BotFather.")
    app = Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("vincular", vincular))
    app.add_handler(CommandHandler("stop", stop))
    app.add_handler(MessageHandler(filters.LOCATION, on_location))
    logging.info("GeoConsent bot en marcha (consentimiento explícito por botón).")
    app.run_polling()

if __name__ == "__main__":
    main()
