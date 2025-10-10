from flask import Flask, request, jsonify, make_response
from google.oauth2.service_account import Credentials
import gspread
import os
from flask_cors import CORS
import secrets
from datetime import datetime
import traceback

# ---------------------------
# Config / environment
# ---------------------------
GOOGLE_CREDS_PATH = os.environ.get("GOOGLE_CREDS_PATH", "credentials.json")
GOOGLE_SHEET_URL = os.environ.get("GOOGLE_SHEET_URL", "")
# Optional: restrict CORS to your frontend origin, e.g. "https://callbridge.vercel.app"
CORS_ALLOWED_ORIGINS = os.environ.get("CORS_ALLOWED_ORIGINS", "*")

# ---------------------------
# Flask app + CORS
# ---------------------------
app = Flask(__name__)
# allow simple CORS for now (you can set CORS_ALLOWED_ORIGINS to a specific origin)
CORS(app, resources={r"/*": {"origins": CORS_ALLOWED_ORIGINS}}, supports_credentials=True)

# Very small in-memory session store: token -> user dict
# NOTE: This is ephemeral (lost when process restarts). Replace with DB or JWT for production.
SESSIONS = {}

# ---------------------------
# Google Sheets setup
# ---------------------------
try:
    creds = Credentials.from_service_account_file(
        GOOGLE_CREDS_PATH,
        scopes=["https://www.googleapis.com/auth/spreadsheets"]
    )
    gc = gspread.authorize(creds)
    if not GOOGLE_SHEET_URL:
        raise RuntimeError("GOOGLE_SHEET_URL environment variable not set.")
    sh = gc.open_by_url(GOOGLE_SHEET_URL)
    users_ws = sh.worksheet("Users")
    calls_ws = sh.worksheet("CallLogs")
except Exception as e:
    # keep app running but any route that touches sheets will return 500 with message
    users_ws = None
    calls_ws = None
    sheet_setup_error = traceback.format_exc()
    print("Google Sheets initialization error:", sheet_setup_error)


# ---------------------------
# Helper functions
# ---------------------------
def get_all_users():
    if users_ws is None:
        raise RuntimeError("Users worksheet not initialized.")
    return users_ws.get_all_records()


def find_user_by_email(email):
    users = get_all_users()
    email = (email or "").strip()
    for u in users:
        # Normalize keys (some spreadsheets may have keys with spaces)
        u_email = u.get("Email") or u.get("email") or ""
        if str(u_email).strip().lower() == email.lower():
            # normalize returned user dict keys used by frontend
            return {
                "id": str(u_email).strip(),
                "email": str(u_email).strip(),
                "display_name": u.get("Display Name") or u.get("display_name") or "",
                "assigned_number": str(u.get("Assigned Number") or u.get("assigned_number") or ""),
                "expiry_date": str(u.get("Expiry Date") or u.get("expiry_date") or ""),
                "role": u.get("Role") or u.get("role") or "user"
            }
    return None


def get_user_by_token(auth_header):
    # expects "Bearer <token>"
    if not auth_header:
        return None
    parts = auth_header.split()
    if len(parts) != 2:
        return None
    token = parts[1]
    return SESSIONS.get(token)


# ---------------------------
# Routes
# ---------------------------
@app.route("/", methods=["GET", "OPTIONS"])
def home():
    return jsonify({"message": "Backend is running!"})


@app.route("/login", methods=["POST", "OPTIONS"])
def login():
    try:
        data = request.get_json(force=True)
        email = (data.get("email") or "").strip()
        password = data.get("password") or ""

        if not email:
            return jsonify({"error": "Email required"}), 400
        if users_ws is None:
            return jsonify({"error": "Server configuration error (sheets)"}), 500

        # find matching user row
        # Note: spreadsheet column names must match "Email" and "Password"
        rows = users_ws.get_all_records()
        for r in rows:
            row_email = (r.get("Email") or "").strip()
            row_password = r.get("Password") or ""
            if row_email.lower() == email.lower() and str(row_password) == str(password):
                user = find_user_by_email(email)
                token = secrets.token_urlsafe(24)
                # store session
                SESSIONS[token] = user
                return jsonify({"token": token, "user": user})

        return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        print("Login error:", traceback.format_exc())
        return jsonify({"error": "Server error during login"}), 500


@app.route("/profile", methods=["GET", "POST", "OPTIONS"])
def profile():
    try:
        # If GET + Authorization header -> return session user
        if request.method == "GET":
            auth = request.headers.get("Authorization", "")
            user = get_user_by_token(auth)
            if not user:
                return jsonify({"error": "Unauthorized"}), 401
            return jsonify(user)

        # If POST, accept {"email": "<email>"} in body
        data = request.get_json(force=True)
        email = (data.get("email") or "").strip()
        if not email:
            return jsonify({"error": "email required"}), 400
        user = find_user_by_email(email)
        if not user:
            return jsonify({"error": "User not found"}), 404
        return jsonify(user)
    except Exception as e:
        print("Profile error:", traceback.format_exc())
        return jsonify({"error": "Server error"}), 500


@app.route("/calls", methods=["GET", "OPTIONS"])
def list_calls():
    try:
        # require Authorization header
        auth = request.headers.get("Authorization", "")
        user = get_user_by_token(auth)
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        email = user.get("email")

        if calls_ws is None:
            return jsonify({"error": "Server configuration error (sheets)"}), 500

        rows = calls_ws.get_all_records()
        # sheet columns: Timestamp From To Duration User Email Call Type Notes
        user_calls = []
        for r in rows:
            if str(r.get("User Email") or "").strip().lower() != email.lower():
                continue
            # map sheet row to frontend-friendly object
            user_calls.append({
                "created_at": r.get("Timestamp") or r.get("timestamp") or "",
                "phone_number": r.get("To") or r.get("to") or r.get("Phone") or "",
                "other_number": r.get("From") or r.get("from") or "",
                "duration": int(r.get("Duration") or 0),
                "status": r.get("Notes") or "",
                "call_type": r.get("Call Type") or r.get("call_type") or "",
            })
        # newest first (try to parse dates; if not, just reverse)
        try:
            user_calls.sort(key=lambda x: x.get("created_at") or "", reverse=True)
        except Exception:
            user_calls = list(reversed(user_calls))
        return jsonify(user_calls)
    except Exception as e:
        print("List calls error:", traceback.format_exc())
        return jsonify({"error": "Server error"}), 500


@app.route("/save-call", methods=["POST", "OPTIONS"])
def save_call():
    try:
        payload = request.get_json(force=True)
        # determine user email (prefer Authorization token)
        user = get_user_by_token(request.headers.get("Authorization", ""))
        if user:
            user_email = user.get("email")
        else:
            user_email = payload.get("user_id") or payload.get("user_email") or payload.get("email")
        if not user_email:
            return jsonify({"error": "user identification required"}), 400

        if calls_ws is None:
            return jsonify({"error": "Server configuration error (sheets)"}), 500

        timestamp = payload.get("created_at") or payload.get("timestamp") or datetime.utcnow().isoformat(sep=" ")
        from_num = payload.get("phone_number") if payload.get("call_type") == "incoming" else (payload.get("from_number") or "")
        to_num = payload.get("phone_number") if payload.get("call_type") == "outgoing" else (payload.get("to_number") or "")
        # ensure something in From/To (sheet expects both columns)
        from_col = payload.get("from") or payload.get("From") or payload.get("caller") or from_num or ""
        to_col = payload.get("to") or payload.get("To") or to_num or ""
        duration = payload.get("duration") or 0
        call_type = payload.get("call_type") or payload.get("type") or ""
        notes = payload.get("status") or payload.get("notes") or ""

        row = [timestamp, from_col, to_col, str(duration), user_email, call_type, notes]
        calls_ws.append_row(row, value_input_option='USER_ENTERED')
        return jsonify({"success": True}), 201
    except Exception as e:
        print("Save call error:", traceback.format_exc())
        return jsonify({"error": "Server error"}), 500


@app.route("/twilio-token", methods=["POST", "OPTIONS"])
def twilio_token():
    try:
        data = request.get_json(force=True)
        # find user (from token or user_id)
        user = get_user_by_token(request.headers.get("Authorization", ""))
        if not user:
            email = (data.get("user_id") or data.get("email") or "").strip()
            user = find_user_by_email(email) if email else None
        if not user:
            # return 401 so frontend knows it cannot get token
            return jsonify({"error": "Unauthorized"}), 401

        # STUB: in production you'd generate a Twilio capability token here
        # Return a placeholder token string (frontend must handle absence gracefully)
        fake_token = "TWILIO_FAKE_TOKEN_PLACEHOLDER"
        return jsonify({"token": fake_token, "callerId": user.get("assigned_number")})
    except Exception as e:
        print("Twilio token error:", traceback.format_exc())
        return jsonify({"error": "Server error"}), 500


# ensure OPTIONS preflight returns OK for any route not handled above
@app.after_request
def add_headers(response):
    response.headers["Access-Control-Allow-Origin"] = CORS_ALLOWED_ORIGINS
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return response


# ---------------------------
# Run
# ---------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
