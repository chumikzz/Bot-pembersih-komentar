import os
import re
import json

# --- Pastikan client_secret.json dibuat sebelum Flask dijalankan ---
client_secret_content = os.getenv("CLIENT_SECRET_JSON")
if client_secret_content:
    with open("client_secret.json", "w") as f:
        f.write(client_secret_content)
    print("✅ client_secret.json berhasil dibuat")
else:
    print("⚠️ CLIENT_SECRET_JSON tidak ditemukan di environment variables!")

from flask import Flask, redirect, request, session, url_for, render_template
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import google.auth.transport.requests
from google.oauth2.credentials import Credentials

# --- Railway & Local Config ---
if os.environ.get("RAILWAY_ENVIRONMENT"):
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "0"  # Enforce HTTPS in Railway
else:
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Allow HTTP locally

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "your_secret_key")

# Kata kunci spam
SPAM_KEYWORDS = [
    'pulau','pulauwin','pluto','plut088','pluto88','probet855',
    'mona','mona4d','alexis17','soundeffect','mudahwin',
    'akunpro','boterpercaya','maxwin','pulau777','weton88',
    'plutowin','plutowinn','pluto8','pulowin','pulauw','plu88',
    'pulautoto','tempatnyaparapemenangsejatiberkumpul',
    'bahkandilaguremix','bergabunglahdenganpulau777',
    '퓟퓤퓛퓐퓤퓦퓘퓝','홿횄홻홰횄횆홸홽'
]

CLIENT_SECRETS_FILE = "client_secret.json"
SCOPES = ["https://www.googleapis.com/auth/youtube.force-ssl"]

@app.route("/")
def index():
    return render_template("index.html", authorized=("credentials" in session))

@app.route("/login")
def login():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=url_for("oauth2callback", _external=True),
    )
    auth_url, _ = flow.authorization_url(prompt="consent")
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=url_for("oauth2callback", _external=True),
    )
    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials
    session["credentials"] = {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": credentials.scopes,
    }
    return redirect(url_for("index"))

@app.route("/clean", methods=["POST"])
def clean_comments():
    creds_data = session.get("credentials")
    if not creds_data:
        return redirect(url_for("login"))

    creds = Credentials(**creds_data)
    youtube = build("youtube", "v3", credentials=creds)

    # Ambil jumlah video yang diminta user
    try:
        video_limit = int(request.form.get("video_limit", 5))
    except ValueError:
        video_limit = 5

    # Ambil Channel ID milik user
    channel_response = youtube.channels().list(
        part="id",
        mine=True
    ).execute()
    if not channel_response.get("items"):
        return "❌ Channel tidak ditemukan untuk akun ini."
    channel_id = channel_response["items"][0]["id"]

    # Ambil daftar video terbaru
    videos_response = youtube.search().list(
        part="id",
        channelId=channel_id,
        maxResults=video_limit,
        order="date",
        type="video"
    ).execute()

    video_ids = [item["id"]["videoId"] for item in videos_response.get("items", [])]

    deleted = 0
    deleted_logs = []

    # Loop tiap video dan ambil komentarnya
    for vid in video_ids:
        comments_response = youtube.commentThreads().list(
            part="snippet",
            videoId=vid,
            maxResults=50,
            textFormat="plainText"
        ).execute()

        for item in comments_response.get("items", []):
            comment = item["snippet"]["topLevelComment"]["snippet"]["textDisplay"]
            comment_id = item["snippet"]["topLevelComment"]["id"]
            video_url = f"https://www.youtube.com/watch?v={vid}"
            if any(keyword.lower() in comment.lower() for keyword in SPAM_KEYWORDS):
                youtube.comments().setModerationStatus(
                    id=comment_id,
                    moderationStatus="rejected"
                ).execute()
                deleted += 1
                deleted_logs.append(f"- {comment} (Video: {video_url})")

    log_text = "<br>".join(deleted_logs) if deleted_logs else "Tidak ada komentar spam yang dihapus."
    return f"✅ {deleted} komentar spam berhasil dihapus dari {len(video_ids)} video terakhir.<br><br><b>Log:</b><br>{log_text}"

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)