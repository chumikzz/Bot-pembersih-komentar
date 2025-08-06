import os
import re
import json
import base64
from flask import Flask, redirect, request, session, url_for, render_template
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import google.auth.transport.requests
from google.oauth2.credentials import Credentials

# --- Railway & Local Config ---
# Untuk development (HTTP) vs production (HTTPS)
if os.environ.get("RAILWAY_ENVIRONMENT"):
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "0"  # Enforce HTTPS di Railway
else:
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Allow HTTP lokal

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "your_secret_key")

# Load dan decode Base64 client secret JSON dari env var
b64 = os.getenv("CLIENT_SECRET_B64")
if not b64:
    raise RuntimeError("Env var CLIENT_SECRET_B64 belum diset dengan Base64 JSON YouTube OAuth client secret.")
try:
    decoded = base64.b64decode(b64).decode('utf-8')
    client_config = json.loads(decoded)
except Exception as e:
    raise RuntimeError(f"Gagal decode CLIENT_SECRET_B64: {e}")

SCOPES = ["https://www.googleapis.com/auth/youtube.force-ssl"]

# SPAM keywords\ nSPAM_KEYWORDS = [
    'pulau','pulauwin','pluto','plut088','pluto88','probet855',
    # ... tambahkan lagi sesuai kebutuhan
]

@app.route("/")
def index():
    return render_template("index.html", authorized=("credentials" in session))

@app.route("/login")
def login():
    flow = Flow.from_client_config(
        client_config,
        scopes=SCOPES,
        redirect_uri=url_for("oauth2callback", _external=True)
    )
    auth_url, _ = flow.authorization_url(prompt="consent")
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    flow = Flow.from_client_config(
        client_config,
        scopes=SCOPES,
        redirect_uri=url_for("oauth2callback", _external=True)
    )
    flow.fetch_token(authorization_response=request.url)

    creds = flow.credentials
    session["credentials"] = {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes,
    }
    return redirect(url_for("index"))

@app.route("/clean", methods=["POST"])
def clean_comments():
    data = session.get("credentials")
    if not data:
        return redirect(url_for("login"))

    creds = Credentials(**data)
    youtube = build("youtube", "v3", credentials=creds)

    # Batas video yang dicek
    try:
        limit = int(request.form.get("video_limit", 5))
    except:
        limit = 5

    # Ambil channel ID
    res = youtube.channels().list(part="id", mine=True).execute()
    if not res.get("items"):
        return "❌ Channel tidak ditemukan"
    cid = res["items"][0]["id"]

    vids = youtube.search().list(
        part="id", channelId=cid, maxResults=limit, order="date", type="video"
    ).execute().get("items", [])
    video_ids = [v["id"]["videoId"] for v in vids]

    deleted = 0
    logs = []
    for vid in video_ids:
        threads = youtube.commentThreads().list(
            part="snippet", videoId=vid, maxResults=50, textFormat="plainText"
        ).execute().get("items", [])
        for it in threads:
            c = it["snippet"]["topLevelComment"]["snippet"]["textDisplay"]
            cid = it["snippet"]["topLevelComment"]["id"]
            if any(k.lower() in c.lower() for k in SPAM_KEYWORDS):
                youtube.comments().setModerationStatus(
                    id=cid, moderationStatus="rejected"
                ).execute()
                deleted += 1
                logs.append(f"- {c} (https://youtu.be/{vid})")

    log_html = '<br>'.join(logs) if logs else 'Tidak ada spam dihapus.'
    return f"✅ {deleted} komentar dihapus dari {len(video_ids)} video.<br><b>Detail:</b><br>{log_html}"

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)
