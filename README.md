# License mini app

Telegram Web App for selling time-limited licenses through Crypto Pay. It deliberately does not collect Telegram account sessions or offer bulk messaging.

## Run

1. Copy `.env.example` to `.env` and enter the bot and Crypto Pay API tokens.
2. `pip install -r requirements.txt`
3. `uvicorn app.main:app --reload`
4. Deploy behind HTTPS, set `WEBHOOK_URL`, then set the resulting URL as the bot's Telegram Web App URL.

For local testing open `http://127.0.0.1:8000`. In Telegram, the signed `initData` determines the buyer. The API refuses a purchase without it, except when `DEV_TELEGRAM_ID` is explicitly set for development.

## Приветствие по `/start`

Set `WEBAPP_URL` to the public Railway domain and create a long `TELEGRAM_WEBHOOK_SECRET`. Configure the Telegram webhook once by opening this URL (replace the placeholders):

`https://api.telegram.org/bot<BOT_TOKEN>/setWebhook?url=https://<YOUR_DOMAIN>/api/telegram/webhook/<TELEGRAM_WEBHOOK_SECRET>&secret_token=<TELEGRAM_WEBHOOK_SECRET>`

The bot will then reply to `/start` with a welcome message and the “Запустить” Mini App button.

## Crypto Pay webhook

Set the Webhooks URL in Crypto Bot → Crypto Pay → your app → Webhooks to the `WEBHOOK_URL` value. The endpoint accepts `update_type=invoice_paid` only on the secret URL, then re-checks every invoice with the Crypto Pay API before activating it. After a successful payment, the bot sends the key to the buyer's private chat. The user must have started the bot once.
