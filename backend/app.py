from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import os, secrets, time, traceback

# Google Sheets
import gspread
from google.oauth2.service_account import Credentials

# Twilio
from twilio.jwt.access_token import AccessToken
from twilio.jwt.access_token.grants import VoiceGrant
from twilio.twiml.voice_response import VoiceResponse, Dial
import phonenumbers  # pip install phonenumbers

# ---------------- Flask App ----------------
app = Flask(__name__)
# Allow all origins for now (tighten to your domain in production)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
@app.before_request
def handle_options():
    if request.method == "OPTIONS":
        resp = app.make_default_options_response()
        headers = None
        if "ACCESS_CONTROL_REQUEST_HEADERS" in request.headers:
            headers = request.headers["ACCESS_CONTROL_REQUEST_HEADERS"]
        h = resp.headers
        h["Access-Control-Allow-Origin"] = "*"
        h["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        h["Access-Control-Allow-Headers"] = headers or "Authorization, Content-Type"
        return resp


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

def find_user_by_assigned_number(num):
    """Return user dict whose Assigned Number matches num (E.164)."""
    try:
        if not num:
            return None
        target = to_e164(str(num), default_region='US')
        rows = users_ws.get_all_records()
        for r in rows:
            assigned = to_e164(str(r.get("Assigned Number", "")).strip(), default_region='US')
            if assigned and assigned == target:
                return {
                    "id": r.get("Email"),
                    "email": r.get("Email"),
                    "display_name": r.get("Display Name"),
                    "assigned_number": assigned,
                    "expiry_date": r.get("Expiry Date"),
                    "role": r.get("Role"),
                }
    except Exception:
        traceback.print_exc()
    return None

def _https_url(url, req):
    # Render/other proxies often set X-Forwarded-Proto=https for HTTPS requests
    proto = req.headers.get("X-Forwarded-Proto", "https")
    if url.startswith("http://") and proto == "https":
        return "https://" + url[len("http://"):]
    return url



@app.after_request
def after_request(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return response

# --- Phone normalization & Sheets RAW append ---

def to_e164(num: str, default_region='US') -> str:
    """Return E.164 (+14155551234). If empty/invalid, return original unchanged."""
    if not num:
        return num
    n = str(num).strip()
    try:
        # If user typed 10 digits, treat as US and add +1
        if n.isdigit() and len(n) == 10 and default_region == 'US':
            n = f"+1{n}"
        parsed = phonenumbers.parse(n, default_region)
        if phonenumbers.is_valid_number(parsed):
            return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    except Exception:
        pass
    return n  # leave as-is if we can't parse

def append_row_raw(ws, row):
    """Append exactly-as-given values (keeps + in Google Sheets)."""
    srow = ["" if v is None else str(v) for v in row]
    ws.append_row(srow, value_input_option='RAW')


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
        # 1) Try Bearer token -> email (works when TOKENS has the entry)
        auth_email = auth_from_token(request.headers.get("Authorization", ""))

        # 2) Fallbacks for when the dyno restarted and TOKENS is empty
        if not auth_email:
            # allow passing email via query or header as a fallback
            auth_email = (request.args.get("email") or
                          request.headers.get("X-User-Email") or "").strip().lower()

        if not auth_email:
            # no identity -> return empty list (keeps UI clean) instead of 401
            return jsonify([])

        # Admins can see all, others only their own rows
        viewer = find_user_by_email(auth_email)
        is_admin = False
        if viewer and str(viewer.get("role", "")).strip().lower() in {"admin", "administrator"}:
            is_admin = True

        rows = calls_ws.get_all_records()
        calls = []
        for r in rows:
            row = {
                "created_at": r.get("Timestamp") or r.get("timestamp") or None,
                "from_number": r.get("From") or r.get("From Number") or r.get("from"),
                "to_number": r.get("To") or r.get("To Number") or r.get("to"),
                "duration": r.get("Duration") or r.get("duration") or 0,
                "user_email": r.get("User Email") or r.get("User") or r.get("user_email"),
                "call_type": r.get("Call Type") or r.get("call_type"),
                "status": r.get("Notes") or r.get("Notes / Status") or r.get("status"),
            }

            if is_admin or (str(row.get("user_email") or "").strip().lower() == auth_email):
                calls.append(row)

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
        # prefer authed email; fall back to explicit email on request if needed
        auth_email = auth_from_token(request.headers.get("Authorization", "")) \
                     or (request.args.get("email") or request.headers.get("X-User-Email") or "").strip().lower()

        data = request.get_json(force=True)
        timestamp = data.get("created_at") or data.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S")
        from_num = data.get("from") or data.get("from_number") or ""
        to_num = data.get("to") or data.get("to_number") or ""
        duration = int(data.get("duration", 0))
        call_type = data.get("call_type") or ""
        notes = data.get("status") or data.get("notes") or ""

        # always bind to the resolved email if present; otherwise use provided
        user_email = auth_email or data.get("user_email") or data.get("user_id") or data.get("user") or ""

        # normalize phone numbers and save RAW to keep '+'
        from_num_e164 = to_e164(from_num, default_region='US')
        to_num_e164   = to_e164(to_num,   default_region='US')

        append_row_raw(
            calls_ws,
            [timestamp, from_num_e164, to_num_e164, duration, user_email, call_type, notes]
        )

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
        raw_caller = user.get("assigned_number") if user else os.environ.get("TWILIO_PHONE_NUMBER")
        caller_id = to_e164(raw_caller, default_region='US')

        return jsonify({"token": jwt, "callerId": caller_id})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500


@app.route("/voice", methods=["POST"])
def voice():
    """Twilio webhook: outgoing (client->PSTN) or incoming (PSTN->client)."""
    try:
        # Use From=client:IDENTITY to detect client-originated calls.
        from_param = request.values.get("From", "") or ""
        is_client_call = from_param.startswith("client:")

        default_caller_id = (
            os.environ.get("TWILIO_CALLER_ID") or
            os.environ.get("TWILIO_PHONE_NUMBER")
        )

        resp = VoiceResponse()

        if is_client_call:
            # ===== OUTGOING: client -> PSTN =====
            outbound_to = request.values.get("To", "") or ""
            requested_caller = request.values.get("CallerId", "")

            identity = from_param.split(":", 1)[1]  # after "client:"
            user = find_user_by_email(identity) if identity else None
            user_assigned = (user or {}).get("assigned_number") if user else None

            caller_id = to_e164(requested_caller or user_assigned or default_caller_id, default_region='US')
            outbound_to = to_e164(outbound_to, default_region='US')

            print(f"[VOICE OUTBOUND] identity={identity!r} caller_id={caller_id} to={outbound_to}")

            dial = Dial(callerId=caller_id)
            dial.number(outbound_to)
            resp.append(dial)

        else:
            # ===== INCOMING: PSTN -> client =====
            called_raw = request.values.get("Called") or request.values.get("To") or ""
            caller_raw = request.values.get("Caller") or request.values.get("From") or ""
            called_e164 = to_e164(called_raw, default_region='US')
            caller_e164 = to_e164(caller_raw, default_region='US')

            print(f"[VOICE INBOUND] Called(raw)={called_raw} -> {called_e164} | From(raw)={caller_raw} -> {caller_e164}")

            target_user = find_user_by_assigned_number(called_e164)
            if not target_user or not target_user.get("email"):
                resp.say("We could not find a destination for this call. Goodbye.")
                print(f"[VOICE INBOUND] No user mapped to {called_e164}")
                return str(resp), 200, {"Content-Type": "application/xml"}

            identity = str(target_user["email"]).strip()
            print(f"[VOICE INBOUND] Routing to identity={identity!r}")

            # Ring the Twilio <Client> (your JS SDK logged in as this email)
dial = Dial(timeout=25)
dial.client(
    identity,
    status_callback=_https_url(f"{request.url_root.rstrip('/')}/client-status", request),
    status_callback_event="initiated ringing answered completed"
)
resp.append(dial)

            

        return str(resp), 200, {"Content-Type": "application/xml"}

    except Exception as e:
        print("Error in /voice:", e)
        return str(VoiceResponse()), 500, {"Content-Type": "application/xml"}





@app.route("/client-status", methods=["POST"])
def client_status():
    # Twilio posts status for attempts to reach the <Client> identity
    try:
        # You will see: CallSid, CallStatus (queued|ringing|in-progress|completed|busy|no-answer|failed), To, From, Timestamp
        print("[CLIENT STATUS]", dict(request.values))
        return ("", 204)
    except Exception as e:
        print("client-status error:", e)
        return ("", 204)




# ---------------- Run ----------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
