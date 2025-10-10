from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import os, secrets, time, traceback

# Google Sheets
import gspread
from google.oauth2.service_account import Credentials

# Twilio
from twilio.jwt.access_token import AccessToken
from twilio.jwt.access_token.grants import VoiceGrant
from twilio.twiml.voice_response import VoiceResponse

# ---------------- Flask App ----------------
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

TOKENS = {}

# ---------------- Google Sheets Setup ----------------
CREDS_FILE = os.environ.get("GOOGLE_CREDS_FILE", "credentials.json")
SHEET_URL = os.environ.get("GOOGLE_SHEET_URL")
if not SHEET_URL:
    raise RuntimeError("Missing GOOGLE_SHEET_URL")

creds = Credentials.from_service_account_file(
    CREDS_FILE,
    scopes=["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"]
)
gc = gspread.authorize(creds)
sh = gc.open_by_url(SHEET_URL)
users_ws = sh.worksheet("Users")
calls_ws = sh.worksheet("CallLogs")

# ---------------- Helpers ----------------
def find_user_by_email(email):
    rows = users_ws.get_all_records()
    for r in rows:
        if str(r.get("Email", "")).strip().lower() == str(email).strip().lower():
            return {
                "id": r.get("Email"),
                "email": r.get("Email"),
                "display_name": r.get("Display Name"),
                "assigned_number": r.get("Assigned Number"),
                "expiry_date": r.get("Expiry Date"),
                "role": r.get("Role"),
            }
    return None

def auth_from_token(header):
    if not header:
        return None
    if header.startswith("Bearer "):
        token = header.split(" ", 1)[1].strip()
        return TOKENS.get(token)
    return None

def _ok_cors():
    resp = make_response("", 200)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return resp

# ---------------- Routes ----------------
@app.after_request
def after_request(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return response

@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Backend is running!"})

# ---------- LOGIN ----------
@app.route("/login", methods=["POST", "OPTIONS"])
def login():
    if request.method == "OPTIONS":
        return _ok_cors()
    try:
        data = request.get_json(force=True)
        email, password = data.get("email"), data.get("password")

        rows = users_ws.get_all_records()
        for r in rows:
            if r.get("Email") == email and str(r.get("Password")) == str(password):
                token = secrets.token_urlsafe(32)
                TOKENS[token] = email
                user = find_user_by_email(email)
                return jsonify({"token": token, "user": user})
        return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# ---------- PROFILE ----------
@app.route("/profile", methods=["POST", "OPTIONS"])
def profile():
    if request.method == "OPTIONS":
        return _ok_cors()
    try:
        data = request.get_json(force=True)
        email = data.get("email")
        user = find_user_by_email(email)
        if user:
            return jsonify(user)
        return jsonify({"error": "User not found"}), 404
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# ---------- CALL HISTORY ----------
@app.route("/calls", methods=["GET", "OPTIONS"])
def get_calls():
    if request.method == "OPTIONS":
        return _ok_cors()
    try:
        rows = calls_ws.get_all_records()
        calls = []
        for r in rows:
            calls.append({
                "created_at": r.get("Timestamp") or r.get("timestamp"),
                "from_number": r.get("From"),
                "to_number": r.get("To"),
                "duration": r.get("Duration"),
                "user_email": r.get("User Email"),
                "call_type": r.get("Call Type"),
                "status": r.get("Notes")
            })
        return jsonify(list(reversed(calls)))
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# ---------- SAVE CALL ----------
@app.route("/save-call", methods=["POST", "OPTIONS"])
def save_call():
    if request.method == "OPTIONS":
        return _ok_cors()
    try:
        d = request.get_json(force=True)
        ts = d.get("created_at") or time.strftime("%Y-%m-%d %H:%M:%S")
        calls_ws.append_row([
            ts, d.get("from"), d.get("to"),
            d.get("duration"), d.get("user_email"),
            d.get("call_type"), d.get("status")
        ])
        return jsonify({"success": True})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# ---------- TWILIO TOKEN ----------
@app.route("/twilio-token", methods=["POST", "OPTIONS"])
def twilio_token():
    if request.method == "OPTIONS":
        return _ok_cors()
    try:
        d = request.get_json(force=True)
        user_id = d.get("user_id")
        if not user_id:
            return jsonify({"error": "user_id required"}), 400

        ACC = os.environ.get("TWILIO_ACCOUNT_SID")
        KEY = os.environ.get("TWILIO_API_KEY_SID")
        SECRET = os.environ.get("TWILIO_API_KEY_SECRET")
        APP_SID = os.environ.get("TWILIO_TWIML_APP_SID")

        token = AccessToken(ACC, KEY, SECRET, identity=user_id)
        voice_grant = VoiceGrant(outgoing_application_sid=APP_SID, incoming_allow=True)
        token.add_grant(voice_grant)

        user = find_user_by_email(user_id)
        caller_id = user.get("assigned_number") if user else os.environ.get("TWILIO_PHONE_NUMBER")

        return jsonify({
            "token": token.to_jwt().decode("utf-8"),
            "callerId": caller_id
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# ---------- TWILIO VOICE WEBHOOK ----------
@app.route("/voice", methods=["POST"])
def voice():
    response = VoiceResponse()
    to_number = request.form.get("To")
    if to_number:
        dial = response.dial(callerId=os.environ.get("TWILIO_PHONE_NUMBER"))
        dial.number(to_number)
    else:
        dial = response.dial()
        dial.client("support")
    return str(response)

# ---------------- Run ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
