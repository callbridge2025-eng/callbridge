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
from twilio.twiml.voice_response import VoiceResponse, Dial

# ---------------- Flask App ----------------
app = Flask(__name__)
# Allow all origins for now (tighten to your domain in production)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# Simple in-memory token map (replace with proper DB/JWT in production)
TOKENS = {}

# ---------------- Google Sheets Setup ----------------
CREDS_FILE = os.environ.get("GOOGLE_CREDS_FILE", "credentials.json")
SHEET_URL = os.environ.get("GOOGLE_SHEET_URL")
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

# ---------------- Helpers ----------------
def find_user_by_email(email):
    try:
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

def _ok_cors():
    resp = make_response("", 200)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return resp

@app.after_request
def after_request(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return response

# ---------------- Routes ----------------
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

        rows = users_ws.get_all_records()
        for r in rows:
            if str(r.get("Email", "")).strip().lower() == str(email).strip().lower() and str(r.get("Password","")) == str(password):
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

@app.route("/profile", methods=["POST", "OPTIONS"])
def profile():
    if request.method == "OPTIONS":
        return _ok_cors()
    try:
        data = request.get_json(force=True)
        email = data.get("email")
        if not email:
            return jsonify({"error": "email required"}), 400
        user = find_user_by_email(email)
        if not user:
            return jsonify({"error": "User not found"}), 404
        return jsonify(user)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500

@app.route("/calls", methods=["GET", "OPTIONS"])
def get_calls():
    if request.method == "OPTIONS":
        return _ok_cors()
    try:
        rows = calls_ws.get_all_records()
        calls = []
        for r in rows:
            calls.append({
                "created_at": r.get("Timestamp") or r.get("timestamp") or None,
                "from_number": r.get("From") or r.get("From Number") or r.get("from"),
                "to_number": r.get("To") or r.get("To Number") or r.get("to"),
                "duration": r.get("Duration") or r.get("duration") or 0,
                "user_email": r.get("User Email") or r.get("User") or r.get("user_email"),
                "call_type": r.get("Call Type") or r.get("call_type"),
                "status": r.get("Notes") or r.get("Notes / Status") or r.get("status")
            })
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
        timestamp = data.get("created_at") or data.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S")
        from_num = data.get("from") or data.get("from_number") or ""
        to_num = data.get("to") or data.get("to_number") or ""
        duration = int(data.get("duration", 0))
        user_email = data.get("user_email") or data.get("user_id") or data.get("user") or ""
        call_type = data.get("call_type") or ""
        notes = data.get("status") or data.get("notes") or ""

        # Append row: Timestamp, From, To, Duration, User Email, Call Type, Notes
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
        if not user_id:
            # if no user_id provided, try auth header
            auth = request.headers.get("Authorization", "")
            user_id = auth_from_token(auth)

        if not user_id:
            return jsonify({"error": "user_id required"}), 400

        ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
        API_KEY_SID = os.environ.get("TWILIO_API_KEY_SID")
        API_KEY_SECRET = os.environ.get("TWILIO_API_KEY_SECRET")
        TWIML_APP_SID = os.environ.get("TWILIO_TWIML_APP_SID")

        if not ACCOUNT_SID or not API_KEY_SID or not API_KEY_SECRET:
            return jsonify({"error": "Twilio configuration missing"}), 500

        token = AccessToken(ACCOUNT_SID, API_KEY_SID, API_KEY_SECRET, identity=str(user_id))
        voice_grant = VoiceGrant(outgoing_application_sid=TWIML_APP_SID, incoming_allow=True)
        token.add_grant(voice_grant)
        jwt = token.to_jwt()
        if isinstance(jwt, bytes):
            jwt = jwt.decode("utf-8")

        user = find_user_by_email(user_id)
        caller_id = user.get("assigned_number") if user else os.environ.get("TWILIO_PHONE_NUMBER")

        return jsonify({"token": jwt, "callerId": caller_id})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500

@app.route("/voice", methods=["POST"])
def voice():
    # Twilio will POST here when making outbound call via TwiML app
    resp = VoiceResponse()
    to_number = request.form.get("To")
    if to_number:
        dial = resp.dial(callerId=os.environ.get("TWILIO_PHONE_NUMBER"))
        dial.number(to_number)
    else:
        # default to client if no To specified
        dial = resp.dial()
        dial.client("support")
    return str(resp)

@app.route("/voice", methods=["POST"])
def voice():
    """Twilio webhook: connects outgoing or incoming calls."""
    try:
        to_number = request.form.get("To")
        from_number = request.form.get("From")

        resp = VoiceResponse()

        if to_number:
            # Outgoing call from web to a phone number
            dial = Dial(callerId=from_number or os.environ.get("TWILIO_CALLER_ID"))
            dial.number(to_number)
            resp.append(dial)
        else:
            # Incoming call (route to client app or default greeting)
            dial = Dial()
            dial.client("client")  # change "client" to your app name if needed
            resp.append(dial)

        return str(resp), 200, {"Content-Type": "application/xml"}
    except Exception as e:
        print("Error in /voice:", e)
        return str(VoiceResponse()), 500, {"Content-Type": "application/xml"}


# ---------------- Run ----------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
