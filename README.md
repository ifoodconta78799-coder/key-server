# Key Server Starter (Flask + SQLite)

Starter project for a license-key API and web admin panel.

## Features
- Admin login
- Create keys valid for 1 hour, 1 day, 7 days, or lifetime
- Revoke keys
- Validate keys via API
- Basic activation counter

## Run locally
Requires Python 3.10+.

```bash
python -m venv .venv
# macOS/Linux:
source .venv/bin/activate
# Windows:
.venv\\Scripts\\activate
pip install -r requirements.txt
```

Set strong secrets before running:

```bash
# macOS/Linux
export ADMIN_PASSWORD='use-a-long-unique-password'
export APP_SECRET='use-a-long-random-secret'
python app.py
```

```powershell
# Windows PowerShell
$env:ADMIN_PASSWORD="use-a-long-unique-password"
$env:APP_SECRET="use-a-long-random-secret"
python app.py
```

Open http://127.0.0.1:5000

## API
Validate a key:

```bash
curl -X POST http://127.0.0.1:5000/api/validate \\
  -H "Content-Type: application/json" \\
  -d '{"key":"YOUR-KEY"}'
```

Activate a key:

```bash
curl -X POST http://127.0.0.1:5000/api/activate \\
  -H "Content-Type: application/json" \\
  -d '{"key":"YOUR-KEY","device_id":"example-device-id"}'
```

## Important limitations before public deployment
- This is a starter, not production-hardened.
- Change default secrets and use HTTPS.
- Put it behind a production WSGI server and configure secure cookies.
- Add rate limiting, audit logs, backups, and CSRF protection.
- Activation counting is a basic counter, not persistent per-device locking yet.
- Never put admin secrets or server credentials inside an IPA/client app.
- The server does not modify or inject code into any IPA. The app must be legitimately integrated with the validation API.
