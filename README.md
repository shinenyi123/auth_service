# Auth Service

Standalone centralized authentication service for future websites. It is the
only service that writes `users`, `otp_codes`, OAuth client/code, and refresh
token records in the shared PostgreSQL database.

## Setup

```powershell
cd auth_service
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python generate_keys.py
python app.py
```

Set real values in `.env`. OTP messages are delivered through the configured
transactional email API over HTTPS; no Gmail password or mail-server configuration is
required. Keep `keys/private_key.pem`, `.env`, and the OAuth client secrets
private. The service uses `DATABASE_URL` from the shared PostgreSQL instance and
migrates legacy dashboard `users`/`otp_codes` column names on startup.

For Render, deploy this directory as its own web service with build command
`pip install -r requirements.txt` and start command `gunicorn app:app`. Set
`DATABASE_URL`, `SECRET_KEY`, `EMAIL_API_KEY`, `EMAIL_API_URL`, `EMAIL_FROM`,
`EMAIL_FROM_NAME`, `INTERNAL_API_KEY`, and a persistent
`PRIVATE_KEY_PATH`/`PUBLIC_KEY_PATH` (or mount the generated key files through
the deployment secret mechanism). `EMAIL_API_URL` must be an HTTPS URL on port
443; the default is Resend's `https://api.resend.com/emails` endpoint.

## Email API

The default provider is Resend because it provides a small-project-friendly
transactional email tier and a simple HTTPS REST API. Create and verify a sender
domain or sender address in Resend, then configure:

```text
EMAIL_API_KEY=re_...
EMAIL_API_URL=https://api.resend.com/emails
EMAIL_FROM=auth@your-verified-domain.example
EMAIL_FROM_NAME=Your Application Name
```

The API key is used only by `email_service.py` and must be stored as a Render
secret. Provider failures are converted into safe application-level errors;
provider response bodies and credentials are not logged or returned to users.

For a local run, copy `.env.example` to `.env`, fill in the email API values,
then run `python app.py`. Registration and password-reset OTP routes both call
the same `email_service.send_otp_email()` abstraction.

## Client registration

Use the internal API with the `X-Internal-API-Key` header:

```powershell
$headers = @{ 'X-Internal-API-Key' = $env:INTERNAL_API_KEY }
Invoke-RestMethod https://auth.example.com/internal/websites -Method Post -Headers $headers -ContentType 'application/json' -Body '{"slug":"student-dashboard","name":"Student Dashboard","base_url":"https://students.example.com"}'
```

Register an OAuth client with the returned `website_id` and an exact callback URL.
The plaintext `client_secret` is returned once and must be stored only by the
client website server.

## Website flow

See [example_client_usage.py](example_client_usage.py). A client redirects the
browser to `/login?client_id=...&redirect_uri=...&state=...`, receives a short-lived
`code` at its callback, exchanges it server-to-server at `/oauth/token`, and
verifies the RS256 access token locally using the cached `/.well-known/jwks.json`
keys. The client must verify its original `state` value.
