from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import os
import secrets
import time
import traceback

# Google Sheets
import gspread
from google.oauth2.service_account import Credentials

# Twilio Access Token
from twilio.jwt.access_token import AccessToken
from twilio.jwt.access_token.grants import VoiceGrant

# ------------- Flask app -------------
app = Flask(__name__)
# allow all origins (adjust to specific origin for production if desired)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# ------------- In-memory token store -------------
# token -> email mapping (simple; replace with persistent store / JWT for production)
TOKENS = {}

# ------------- Google Sheets setup -------------
# Expect credentials.json present in app root (don't commit to git)
CREDS_FILE = os.environ.get("GOOGLE_CREDS_FILE", "credentials.json")
SHEET_URL = os.environ.get("GOOGLE_SHEET_URL", None)

if not SHEET_URL:
    raise RuntimeError("Missing GOOGLE_SHEET_URL environment variable")

try:
    creds = Credentials.from_service_account_file(
        CREDS_FILE,
        scopes=["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"]
    )
    gc = gspread.authorize(creds)
    sh = gc.open_by_url(SHEET_URL)
    users_ws = sh.worksheet("Users")
    calls_ws = sh.worksheet("CallLogs")
except Exception as e:
    print("Error initializing Google Sheets:", e)
    raise

# ------------- Helpers -------------
def find_user_by_email(email):
    try:
        rows = users_ws.get_all_records()
        for r in rows:
            if str(r.get("Email", "")).strip().lower() == str(email).strip().lower():
                # standardize keys used by frontend
                return {
                    "id": r.get("Email"),
                    "email": r.get("Email"),
                    "display_name": r.get("Display Name"),
                    "assigned_number": r.get("Assigned Number"),
                    "expiry_date": r.get("Expiry Date"),
                    "role": r.get("Role"),
                }
    except Exception:
        traceback.print_exc()
    return None

def auth_from_token(header):
    if not header:
        return None
    if header.startswith("Bearer "):
        token = header.split(" ", 1)[1].strip()
        return TOKENS.get(token)
    return None

# ------------- Routes -------------

@app.after_request
def add_cors_headers(response):
    # Ensure these headers to satisfy preflight when necessary
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return response

@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Backend is running!"})

@app.route("/login", methods=["POST", "OPTIONS"])
def login():
    if request.method == "OPTIONS":
        return _ok_cors()
    try:
        data = request.get_json(force=True)
        email = data.get("email")
        password = data.get("password")
        if not email or not password:
            return jsonify({"error": "email and password required"}), 400

        # fetch users from sheet
        rows = users_ws.get_all_records()
        for r in rows:
            if str(r.get("Email", "")).strip().lower() == str(email).strip().lower() and str(r.get("Password","")) == str(password):
                # create token
                token = secrets.token_urlsafe(32)
                TOKENS[token] = r.get("Email")
                user = {
                    "id": r.get("Email"),
                    "email": r.get("Email"),
                    "display_name": r.get("Display Name"),
                    "assigned_number": r.get("Assigned Number"),
                    "expiry_date": r.get("Expiry Date"),
                    "role": r.get("Role"),
                }
                return jsonify({"token": token, "user": user})

        return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500

@app.route("/profile", methods=["GET", "POST", "OPTIONS"])
def profile():
    if request.method == "OPTIONS":
        return _ok_cors()
    try:
        # 1) If POST with JSON containing email -> return profile by email (frontend uses this)
        if request.method == "POST":
            data = request.get_json(force=True)
            email = data.get("email")
            if not email:
                return jsonify({"error": "email required"}), 400
            user = find_user_by_email(email)
            if not user:
                return jsonify({"error": "User not found"}), 404
            return jsonify(user)

        # 2) If GET with Authorization Bearer <token> -> return profile for token
        auth = request.headers.get("Authorization", "")
        email = auth_from_token(auth)
        if email:
            user = find_user_by_email(email)
            if user:
                return jsonify(user)
            else:
                return jsonify({"error": "User not found"}), 404
        return jsonify({"error": "Unauthorized"}), 401
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500

@app.route("/calls", methods=["GET", "OPTIONS"])
def get_calls():
    if request.method == "OPTIONS":
        return _ok_cors()
    try:
        # optional: return all calls or filter by user (query or token)
        auth = request.headers.get("Authorization", "")
        email = auth_from_token(auth)
        rows = calls_ws.get_all_records()
        # map to consistent keys expected by frontend
        calls = []
        for r in rows:
            calls.append({
                "created_at": r.get("Timestamp") or r.get("timestamp") or r.get("Timestamp (UTC)") or None,
                "from_number": r.get("From") or r.get("from") or r.get("From Number"),
                "to_number": r.get("To") or r.get("to") or r.get("To Number"),
                "duration": r.get("Duration") or r.get("duration") or 0,
                "user_email": r.get("User Email") or r.get("User") or r.get("user_email"),
                "call_type": r.get("Call Type") or r.get("call_type"),
                "status": r.get("Notes") or r.get("Notes / Status") or r.get("status")
            })
        # if email present, filter to that user
        if email:
            calls = [c for c in calls if (c.get("user_email") or "").strip().lower() == email.strip().lower()]
        # return most recent first
        calls = list(reversed(calls))
        return jsonify(calls)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500

@app.route("/save-call", methods=["POST", "OPTIONS"])
def save_call():
    if request.method == "OPTIONS":
        return _ok_cors()
    try:
        data = request.get_json(force=True)
        # expected fields: created_at/timestamp, phone_number/from/to, duration, user_email, call_type, status/notes
        timestamp = data.get("created_at") or data.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S")
        from_num = data.get("phone_number") if data.get("call_type") == "incoming" else (data.get("from") or "")
        to_num = data.get("phone_number") if data.get("call_type") == "outgoing" else (data.get("to") or "")
        # graceful fallback
        from_num = from_num or data.get("from") or ""
        to_num = to_num or data.get("to") or ""
        duration = int(data.get("duration", 0))
        user_email = data.get("user_email") or data.get("user_id") or data.get("user") or ""
        call_type = data.get("call_type") or ""
        notes = data.get("status") or data.get("notes") or ""

        # Append in the order matching your sheet: Timestamp From To Duration User Email Call Type Notes
        calls_ws.append_row([timestamp, from_num, to_num, duration, user_email, call_type, notes])
        return jsonify({"success": True})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500

@app.route("/twilio-token", methods=["POST", "OPTIONS"])
def twilio_token():
    if request.method == "OPTIONS":
        return _ok_cors()
    try:
        data = request.get_json(force=True)
        user_id = data.get("user_id") or data.get("user") or None
        # If no user_id provided, try from Authorization token
        if not user_id:
            auth = request.headers.get("Authorization", "")
            email = auth_from_token(auth)
            user_id = email

        if not user_id:
            return jsonify({"error": "user_id required"}), 400

        # required env vars
        ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
        API_KEY_SID = os.environ.get("TWILIO_API_KEY_SID")
        API_KEY_SECRET = os.environ.get("TWILIO_API_KEY_SECRET")
        TWIML_APP_SID = os.environ.get("TWILIO_TWIML_APP_SID")

        if not ACCOUNT_SID or not API_KEY_SID or not API_KEY_SECRET:
            return jsonify({"error": "Twilio configuration missing"}), 500

        # create AccessToken
        token = AccessToken(ACCOUNT_SID, API_KEY_SID, API_KEY_SECRET, identity=str(user_id))
        voice_grant = VoiceGrant(outgoing_application_sid=TWIML_APP_SID, incoming_allow=True)
        token.add_grant(voice_grant)
        jwt = token.to_jwt().decode("utf-8") if isinstance(token.to_jwt(), bytes) else token.to_jwt()

        # Also find user's assigned number (for callerId)
        user = find_user_by_email(user_id)
        caller_id = user.get("assigned_number") if user else None

        return jsonify({"token": jwt, "callerId": caller_id})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500

# small helper for preflight
def _ok_cors():
    resp = make_response("", 200)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return resp

# ------------- Run -------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
