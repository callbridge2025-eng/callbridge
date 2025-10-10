# app.py
from flask import Flask, request, jsonify, make_response
from google.oauth2.service_account import Credentials
import gspread
import os
from flask_cors import CORS
from datetime import datetime
import traceback

app = Flask(__name__)

# Allow CORS from your frontend (you can restrict origins if desired)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# ---- CONFIG ----
# Path to the service account JSON file. Upload it to Render and name it 'credentials.json'
GOOGLE_CREDENTIALS_FILE = os.environ.get("GOOGLE_CREDENTIALS_FILE", "credentials.json")

# Use env var for sheet URL (set this in Render). Fallback placeholder if not set.
SHEET_URL = os.environ.get("GOOGLE_SHEET_URL", "https://docs.google.com/spreadsheets/d/YOUR_SHEET_ID_HERE/edit")

# ---- Initialize Google Sheets client ----
try:
    creds = Credentials.from_service_account_file(
        GOOGLE_CREDENTIALS_FILE,
        scopes=["https://www.googleapis.com/auth/spreadsheets"]
    )
    gc = gspread.authorize(creds)
    sh = gc.open_by_url(SHEET_URL)
    users_ws = sh.worksheet("Users")
    calls_ws = sh.worksheet("CallLogs")
except Exception as e:
    # Keep app running but log errors so Render logs show what's wrong
    users_ws = None
    calls_ws = None
    print("Google Sheets initialization error:", e)
    traceback.print_exc()


# ---- Helpers ----
def get_all_users():
    if not users_ws:
        return []
    try:
        return users_ws.get_all_records()
    except Exception as e:
        print("Error reading Users worksheet:", e)
        return []

def find_user_by_email(email):
    users = get_all_users()
    for u in users:
        # gspread returns header keys exactly as spreadsheet headers.
        # Accept either "Email" or lowercase "email" to be tolerant.
        if (u.get("Email") or u.get("email") or "").strip().lower() == (email or "").strip().lower():
            return u
    return None

def token_for_email(email):
    # Simple token encoding: "token:<email>"
    # This is intentionally simple so frontend can use it immediately.
    return f"token:{email}"

def email_from_token(token):
    if not token: return None
    if token.startswith("token:"):
        return token.split("token:", 1)[1]
    return None

def append_call_log(row_dict):
    if not calls_ws:
        return False, "CallLogs worksheet not configured"
    try:
        # Ensure order/headers — append as list matching existing headers
        headers = calls_ws.row_values(1)
        if not headers:
            # If no headers present, create them from keys
            headers = list(row_dict.keys())
            calls_ws.insert_row(headers, 1)
        row = [row_dict.get(h, "") for h in headers]
        calls_ws.append_row(row)
        return True, None
    except Exception as e:
        print("Error appending call log:", e)
        traceback.print_exc()
        return False, str(e)


# ---- Routes ----
@app.route("/")
def home():
    return jsonify({"message": "Backend is running!"})


@app.route("/login", methods=["POST", "OPTIONS"])
def login():
    # Accept POST { email, password }
    if request.method == "OPTIONS":
        return _build_cors_preflight_response()

    try:
        data = request.get_json(force=True, silent=True) or {}
        email = (data.get("email") or "").strip()
        password = data.get("password") or ""

        if not email or not password:
            return _corsify_resp(jsonify({"error": "email and password required"}), 400)

        user = find_user_by_email(email)
        if not user:
            return _corsify_resp(jsonify({"error": "Invalid credentials"}), 401)

        # Spreadsheet column might be 'Password' or 'password'
        stored_pw = user.get("Password") or user.get("password") or ""
        if str(stored_pw) != str(password):
            return _corsify_resp(jsonify({"error": "Invalid credentials"}), 401)

        # Build response expected by your frontend
        user_response = {
            "id": (user.get("Email") or user.get("email") or email),
            "email": (user.get("Email") or user.get("email") or email),
            "display_name": user.get("Display Name") or user.get("display_name") or "",
            "assigned_number": str(user.get("Assigned Number") or user.get("assigned_number") or ""),
            "expiry_date": user.get("Expiry Date") or user.get("expiry_date") or "",
            "role": user.get("Role") or user.get("role") or "user"
        }

        token = token_for_email(user_response["email"])

        return _corsify_resp(jsonify({"token": token, "user": user_response}), 200)
    except Exception as e:
        print("Login error:", e)
        traceback.print_exc()
        return _corsify_resp(jsonify({"error": "Server error"}), 500)


@app.route("/profile", methods=["GET", "POST", "OPTIONS"])
def profile():
    # GET: read Authorization Bearer token and return user
    # POST: accept { email } (some frontends call POST)
    if request.method == "OPTIONS":
        return _build_cors_preflight_response()

    try:
        if request.method == "POST":
            data = request.get_json(force=True, silent=True) or {}
            email = (data.get("email") or "").strip()
        else:
            # GET: try Authorization header
            auth = request.headers.get("Authorization") or ""
            if auth.lower().startswith("bearer "):
                token = auth.split(None, 1)[1]
                email = email_from_token(token)
            else:
                email = None

        if not email:
            return _corsify_resp(jsonify({"error": "Missing or invalid token / email"}), 400)

        user = find_user_by_email(email)
        if not user:
            return _corsify_resp(jsonify({"error": "User not found"}), 404)

        user_response = {
            "email": user.get("Email") or user.get("email") or email,
            "display_name": user.get("Display Name") or user.get("display_name") or "",
            "assigned_number": str(user.get("Assigned Number") or user.get("assigned_number") or ""),
            "expiry_date": user.get("Expiry Date") or user.get("expiry_date") or "",
            "role": user.get("Role") or user.get("role") or "user"
        }
        return _corsify_resp(jsonify(user_response), 200)
    except Exception as e:
        print("Profile error:", e)
        traceback.print_exc()
        return _corsify_resp(jsonify({"error": "Server error"}), 500)


@app.route("/calls", methods=["GET", "OPTIONS"])
def get_calls():
    # GET /calls returns call rows for the authenticated user (by Authorization Bearer token)
    if request.method == "OPTIONS":
        return _build_cors_preflight_response()
    try:
        auth = request.headers.get("Authorization") or ""
        email = None
        if auth.lower().startswith("bearer "):
            token = auth.split(None, 1)[1]
            email = email_from_token(token)
        else:
            # allow query param fallback ?email=
            email = request.args.get("email")

        if not email:
            return _corsify_resp(jsonify({"error": "Missing token/email"}), 400)

        if not calls_ws:
            return _corsify_resp(jsonify([]), 200)

        rows = calls_ws.get_all_records()
        # Try to select rows related to this user. We don't know exact header names,
        # so look for "User Email" or "From" match, or a column that contains the email.
        result = []
        for r in rows:
            # Accept several column names
            uemail = (r.get("User Email") or r.get("user_email") or r.get("Email") or r.get("email") or "").strip()
            if uemail and uemail.lower() == email.lower():
                result.append(r)
                continue
            # Also match if From/To contain assigned number for that user (best-effort)
            # If nothing found, skip.
        # If nothing found, return last 20 calls as fallback
        if not result:
            result = rows[-50:] if rows else []
        return _corsify_resp(jsonify(result), 200)
    except Exception as e:
        print("get_calls error:", e)
        traceback.print_exc()
        return _corsify_resp(jsonify({"error": "Server error"}), 500)


@app.route("/save-call", methods=["POST", "OPTIONS"])
def save_call():
    if request.method == "OPTIONS":
        return _build_cors_preflight_response()
    try:
        data = request.get_json(force=True, silent=True) or {}
        # Accept fields like: user_id / user_email, call_type, phone_number, status, created_at, duration, notes
        row = {
            "Timestamp": data.get("created_at") or data.get("timestamp") or datetime.utcnow().isoformat(),
            "From": data.get("from") or "",
            "To": data.get("phone_number") or data.get("to") or "",
            "Duration": data.get("duration") or "",
            "User Email": data.get("user_email") or data.get("user_id") or data.get("user") or "",
            "Call Type": data.get("call_type") or data.get("type") or "",
            "Notes": data.get("notes") or data.get("status") or ""
        }
        ok, err = append_call_log(row)
        if not ok:
            return _corsify_resp(jsonify({"error": err or "Failed to save"}), 500)
        return _corsify_resp(jsonify({"success": True}), 200)
    except Exception as e:
        print("save_call error:", e)
        traceback.print_exc()
        return _corsify_resp(jsonify({"error": "Server error"}), 500)


@app.route("/twilio-token", methods=["POST", "OPTIONS"])
def twilio_token():
    # Return a short-lived Twilio token for Twilio JS SDK in production you'd generate JWT via Twilio.
    # For now, return a dummy token and callerId so frontend can initialize (if needed).
    if request.method == "OPTIONS":
        return _build_cors_preflight_response()
    try:
        data = request.get_json(force=True, silent=True) or {}
        user_id = data.get("user_id") or ""
        # find user and return assigned number as callerId
        user = find_user_by_email(user_id) or find_user_by_email((user_id.get("email") if isinstance(user_id, dict) else user_id) or "")
        callerId = ""
        if user:
            callerId = str(user.get("Assigned Number") or user.get("assigned_number") or "")
        # NOTE: Replace this with proper Twilio Access Token generation in production.
        return _corsify_resp(jsonify({"token": "twilio-dummy-token", "callerId": callerId}), 200)
    except Exception as e:
        print("twilio-token error:", e)
        traceback.print_exc()
        return _corsify_resp(jsonify({"error": "Server error"}), 500)


@app.route("/logout", methods=["POST", "OPTIONS"])
def logout():
    if request.method == "OPTIONS":
        return _build_cors_preflight_response()
    # frontend currently doesn't rely on server logout. Just return success.
    return _corsify_resp(jsonify({"success": True}), 200)


# ---- helpers for CORS-safe responses ----
def _build_cors_preflight_response():
    response = make_response()
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
    response.headers.add("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
    return response

def _corsify_resp(response, status=200):
    # Flask jsonify already returns a Response. We need to add CORS headers for safe cross-site calls.
    response.status_code = status
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
    response.headers.add("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
    return response


# ---- Run ----
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
