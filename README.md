# Backend (FastAPI) - N-device session demo

## Overview
This FastAPI backend provides endpoints to:
- register a device session (`POST /api/register`)
- list sessions (`GET /api/sessions`)
- force logout a session (`POST /api/force_logout`)
- access a protected resource (`GET /api/private`)

It uses a local SQLite database `sessions.db` to track device sessions for each user (by `sub` claim in the ID token).

## Run locally (demo)
1. Create a virtualenv and install requirements:
   ```
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. Run server:
   ```
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```

## Notes
- For demo purposes token verification is not performed. In production you must validate token signature and claims using Auth0's JWKS (see README in root for guidance).
