# VulnAgent React Frontend

This is the replacement UI for the Streamlit prototype. It talks to the VulnAgent
application API, which then calls the Harness, SQLite, and IDA backend.

## Start

Terminal 1: IDA backend.

```powershell
python -m vulnagent serve --idb "E:\path\to\sample.i64" --host 127.0.0.1 --port 8765 --read-only
```

Terminal 2: VulnAgent application API.

```powershell
python -m vulnagent api --host 127.0.0.1 --port 8787
```

Terminal 3: React frontend.

```powershell
cd frontend
npm install
npm run dev
```

Open:

```text
http://127.0.0.1:5173
```

## API

The frontend calls `http://127.0.0.1:8787` by default.

Set `VITE_VULNAGENT_API_BASE` if the application API runs somewhere else.
