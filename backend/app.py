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
from twilio.rest import Client  # <-- NEW for SMS


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
    sms_ws = sh.worksheet("SMSLogs")
    voicemails_ws = sh.worksheet("Voicemails")
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
        target = to_e164(str(num))
        rows = users_ws.get_all_records()
        for r in rows:
            assigned = to_e164(str(r.get("Assigned Number", "")).strip())
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


def _coerce_int(v, default=0):
    try:
        if v is None:
            return default
        s = str(v).strip()
        if s == "":
            return default
        # handles "12", "12.0", 12, 12.0
        return int(float(s))
    except Exception:
        return default

def _get_first_key(d: dict, candidates):
    """Return the first present key (case-insensitive) from candidates."""
    lower = {k.lower(): k for k in d.keys()}
    for c in candidates:
        k = lower.get(c.lower())
        if k is not None:
            return d.get(k)
    return None



# --- Phone normalization & Sheets RAW append ---

def to_e164(num: str) -> str:
    """
    Very simple, multi-country normalizer.
    - Keeps/creates E.164 like +441234567890
    - Does NOT guess country (no US default).
    - You MUST store numbers in sheet as +<countrycode><number>.
    """
    if not num:
        return ""

    s = str(num).strip()
    if s == "":
        return ""

    # Remove spaces, dashes, etc.
    digits_plus = "".join(ch for ch in s if ch.isdigit() or ch == "+")

    # If already like +123..., just keep + and digits
    if digits_plus.startswith("+"):
        # Ensure only one leading + and then digits
        digits = "".join(ch for ch in digits_plus[1:] if ch.isdigit())
        return "+" + digits if digits else ""

    # If starts with 00 (international format), convert to +...
    if digits_plus.startswith("00"):
        digits = "".join(ch for ch in digits_plus[2:] if ch.isdigit())
        return "+" + digits if digits else ""

    # Otherwise: assume the string already has full country code,
    # just add +
    digits = "".join(ch for ch in digits_plus if ch.isdigit())
    if not digits:
        return ""
    return "+" + digits


def append_row_raw(ws, row):
    """Append exactly-as-given values (keeps + in Google Sheets)."""
    srow = ["" if v is None else str(v) for v in row]
    ws.append_row(srow, value_input_option='RAW')


def get_twilio_client():
    """
    Simple helper to create Twilio REST client for SMS.
    Uses TWILIO_ACCOUNT_SID + TWILIO_AUTH_TOKEN from env.
    """
    account_sid = os.environ.get("TWILIO_ACCOUNT_SID")
    auth_token = os.environ.get("TWILIO_AUTH_TOKEN")
    if not account_sid or not auth_token:
        raise RuntimeError("Twilio SMS credentials missing (TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN).")
    return Client(account_sid, auth_token)



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

@app.route("/change-password", methods=["POST", "OPTIONS"])
def change_password():
    if request.method == "OPTIONS":
        return _ok_cors()
    try:
        data = request.get_json(force=True)
        old_password = data.get("old_password") or data.get("oldPassword") or ""
        new_password = data.get("new_password") or data.get("newPassword") or ""
        confirm_password = data.get("confirm_password") or data.get("confirmPassword") or ""

        if not old_password or not new_password or not confirm_password:
            return jsonify({"error": "old_password, new_password and confirm_password are required"}), 400

        if new_password != confirm_password:
            return jsonify({"error": "New password and confirmation do not match"}), 400

        # Resolve authenticated email (Bearer token or fallback header/param)
        auth_email = auth_from_token(request.headers.get("Authorization", "")) \
                     or (request.args.get("email") or request.headers.get("X-User-Email") or "").strip().lower()

        # If no auth header, also accept email in body (keeps parity with other endpoints)
        if not auth_email:
            auth_email = (data.get("email") or data.get("user_email") or data.get("user") or "").strip().lower()

        if not auth_email:
            return jsonify({"error": "User identity required"}), 400

        # Read sheet values (we need row indices)
        all_vals = users_ws.get_all_values()
        if not all_vals or len(all_vals) < 1:
            return jsonify({"error": "Users sheet empty or missing headers"}), 500

        headers = all_vals[0]
        # find column indices (0-based)
        email_col = next((i for i, h in enumerate(headers) if str(h).strip().lower() == "email"), None)
        password_col = next((i for i, h in enumerate(headers) if str(h).strip().lower() == "password"), None)

        if email_col is None or password_col is None:
            return jsonify({"error": "Users sheet must have 'Email' and 'Password' columns"}), 500

        # Find the user's row (sheet rows are 1-indexed)
        for row_idx, row in enumerate(all_vals[1:], start=2):  # start=2 because header is row 1
            cell_email = (row[email_col] if len(row) > email_col else "") or ""
            if str(cell_email).strip().lower() == auth_email.strip().lower():
                current_pw = (row[password_col] if len(row) > password_col else "") or ""
                if str(current_pw) != str(old_password):
                    return jsonify({"error": "Old password does not match"}), 403

                # Update the password cell (update_cell uses 1-based col index)
                users_ws.update_cell(row_idx, password_col + 1, str(new_password))
                return jsonify({"success": True, "message": "Password updated"}), 200

        return jsonify({"error": "User not found"}), 404

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
        from_num_e164 = to_e164(from_num)
        to_num_e164   = to_e164(to_num)

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
        caller_id = to_e164(raw_caller)

        return jsonify({"token": jwt, "callerId": caller_id})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500


@app.route("/voice", methods=["POST"])
def voice():
    """Twilio webhook: outgoing (client->PSTN) or incoming (PSTN->client)."""
    try:
        from_param = request.values.get("From", "") or ""
        is_client_call = from_param.startswith("client:")

        default_caller_id = (
            os.environ.get("TWILIO_CALLER_ID") or
            os.environ.get("TWILIO_PHONE_NUMBER")
        )

        resp = VoiceResponse()

        # 👇 This line MUST be indented with **4 spaces** (same as the 'resp =' above)
        if is_client_call:
            # ===== OUTGOING: client -> PSTN =====
            outbound_to = request.values.get("To", "") or ""
            requested_caller = request.values.get("CallerId", "")

            identity = from_param.split(":", 1)[1] if ":" in from_param else ""
            user = find_user_by_email(identity) if identity else None
            user_assigned = (user or {}).get("assigned_number") if user else None

            caller_id = to_e164(requested_caller or user_assigned or default_caller_id)
            outbound_to = to_e164(outbound_to)

            print(f"[VOICE OUTBOUND] identity={identity!r} caller_id={caller_id} to={outbound_to}")


            # Outbound with voicemail detection
            dial = Dial(callerId=caller_id, answer_on_bridge=True, timeout=40)
            dial.number(
                outbound_to,
                machine_detection="DetectMessageEnd",
                machine_detection_timeout="45",
                url=_https_url(f"{request.url_root.rstrip('/')}/vm-screen", request),
                method="POST"
            )
            resp.append(dial)

        else:
            # ===== INCOMING: PSTN -> client =====
            called_raw = request.values.get("Called") or request.values.get("To") or ""
            caller_raw = request.values.get("Caller") or request.values.get("From") or ""
            called_e164 = to_e164(called_raw)
            caller_e164 = to_e164(caller_raw)

            print(f"[VOICE INBOUND] Called(raw)={called_raw} -> {called_e164} | From(raw)={caller_raw} -> {caller_e164}")

            target_user = find_user_by_assigned_number(called_e164)
            if not target_user or not target_user.get("email"):
                resp.say("We could not find a destination for this call. Goodbye.")
                print(f"[VOICE INBOUND] No user mapped to {called_e164}")
                return str(resp), 200, {"Content-Type": "application/xml"}

            identity = str(target_user["email"]).strip()
            print(f"[VOICE INBOUND] Routing to identity={identity!r}")

            dial = Dial(
                timeout=25,
                action=_https_url(f"{request.url_root.rstrip('/')}/dial-action", request),
                method="POST"
            )
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
    """
    Status callback for <Dial><Client>. Twilio posts here with:
      - CallStatus: ringing | in-progress | completed
      - DialCallStatus: completed | no-answer | busy | failed (final result of dialing the Client)
      - From: PSTN caller (E.164)
      - To:   client:<identity> we dialed (your user's email as identity)
    We log a missed call when DialCallStatus is no-answer/busy/failed.
    """
    try:
        data = request.values.to_dict()
        print("[CLIENT STATUS]", data)

        call_status = (data.get("CallStatus") or "").lower()              # 'ringing'|'in-progress'|'completed'
        dial_call_status = (data.get("DialCallStatus") or "").lower()      # 'completed'|'no-answer'|'busy'|'failed'
        from_number_raw = data.get("From") or ""
        to_raw = data.get("To") or data.get("Called") or ""

        # Extract the Client identity ("client:someone@example.com" -> "someone@example.com")
        identity = to_raw.split(":", 1)[1] if to_raw.startswith("client:") else to_raw

        # Only act when the attempt to reach the Client has finished and was not answered
        if call_status == "completed" and dial_call_status in {"no-answer", "busy", "failed"}:
            # Find which user this client identity belongs to
            user_email = ""
            assigned_e164 = ""
            if identity:
                u = find_user_by_email(identity)
                if u:
                    user_email = u.get("email") or ""
                    assigned_e164 = to_e164(u.get("assigned_number") or "")

            # Fallback: if we didn't resolve the user, still write a row with whatever we have
            from_e164 = to_e164(from_number_raw)
            to_e164_num = assigned_e164 or to_e164(to_raw)

            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            append_row_raw(
                calls_ws,
                [timestamp, from_e164, to_e164_num, 0, user_email, "incoming", f"Missed ({dial_call_status})"]
            )
            print(f"[CLIENT STATUS] Missed call logged: from={from_e164} to={to_e164_num} user={user_email}")

        return ("", 204)
    except Exception as e:
        print("client-status error:", e)
        return ("", 204)


@app.route("/dial-action", methods=["POST"])
def dial_action():
    """
    Called by Twilio after <Dial> finishes (we set 'action' on <Dial>).
    We log a missed call when DialCallStatus is no-answer/busy/failed, and
    then send the caller to voicemail so they can leave a recording.
    """
    try:
        data = request.values.to_dict()
        print("[DIAL ACTION]", data)

        dial_status = (data.get("DialCallStatus") or "").lower()   # completed|no-answer|busy|failed

        # If the client answered, do nothing special
        if dial_status not in {"no-answer", "busy", "failed"}:
            return str(VoiceResponse()), 200, {"Content-Type": "application/xml"}

        from_raw = data.get("From") or ""
        called_raw = data.get("Called") or data.get("To") or ""   # Twilio DID on parent leg

        # Normalize numbers
        from_e164 = to_e164(from_raw)
        called_e164 = to_e164(called_raw)

        # Map the Twilio DID -> user
        user = find_user_by_assigned_number(called_e164)
        user_email = (user or {}).get("email") or ""

        # Write missed-call row in CallLogs sheet
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        append_row_raw(
            calls_ws,
            [timestamp, from_e164, called_e164, 0, user_email, "incoming", f"Missed ({dial_status})"]
        )
        print(f"[DIAL ACTION] Missed call logged: from={from_e164} to={called_e164} user={user_email}")

        # Now send caller to voicemail
        resp = VoiceResponse()
        resp.say(
            "Sorry, the person you are calling can't take your call right now. "
            "Please leave a message after the tone, then press the pound key.",
            voice="alice"
        )
        resp.record(
            max_length=120,
            play_beep=True,
            finish_on_key="#",
            recording_status_callback=_https_url(f"{request.url_root.rstrip('/')}/vm-recording", request),
            recording_status_callback_method="POST"
        )
        resp.hangup()

        return str(resp), 200, {"Content-Type": "application/xml"}

    except Exception as e:
        print("dial-action error:", e)
        return str(VoiceResponse()), 200, {"Content-Type": "application/xml"}



@app.post("/vm-screen")
def vm_screen():
    """
    Callee-leg handler. If voicemail is detected, wait through the greeting/beep,
    then return empty TwiML so Twilio bridges the caller to the voicemail IMMEDIATELY.
    """
    try:
        answered_by = (request.values.get("AnsweredBy") or "").lower()
        print(">> /vm-screen hit AnsweredBy=", request.values.get("AnsweredBy"))
        vr = VoiceResponse()

        if answered_by.startswith("machine_end_") or answered_by.startswith("machine"):
            # Small pause to be safely past the beep—then bridge
            vr.pause(length=1)
            # Return empty <Response/> → Twilio bridges the legs now (post-beep)
            return str(vr), 200, {"Content-Type": "application/xml"}

        # Human or unknown → also return empty so it bridges normally
        return str(vr), 200, {"Content-Type": "application/xml"}

    except Exception as e:
        print("vm-screen error:", e)
        # Fail-open: let Twilio bridge
        return str(VoiceResponse()), 200, {"Content-Type": "application/xml"}


@app.route("/send-sms", methods=["POST", "OPTIONS"])
def send_sms():
    if request.method == "OPTIONS":
        return _ok_cors()
    try:
        data = request.get_json(force=True)
        to_raw = data.get("to") or data.get("to_number")
        body = data.get("body") or data.get("message")

        if not to_raw or not body:
            return jsonify({"error": "to and body are required"}), 400

        # Resolve who is sending
        auth_email = auth_from_token(request.headers.get("Authorization", "")) \
                     or (request.args.get("email") or request.headers.get("X-User-Email") or "").strip().lower()

        user = find_user_by_email(auth_email) if auth_email else None

        # From: user's assigned number, fallback to env SMS/Twilio number
        from_raw = (user or {}).get("assigned_number") \
                   or os.environ.get("TWILIO_SMS_NUMBER") \
                   or os.environ.get("TWILIO_PHONE_NUMBER")

        from_e164 = to_e164(from_raw)
        to_e164_num = to_e164(to_raw)

        client = get_twilio_client()
        msg = client.messages.create(
            to=to_e164_num,
            from_=from_e164,
            body=body
        )

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        user_email = auth_email or (user or {}).get("email") or ""

        append_row_raw(
            sms_ws,
            [timestamp, "outgoing", from_e164, to_e164_num, body, user_email, msg.status or "queued", msg.sid]
        )

        return jsonify({"success": True, "sid": msg.sid}), 200
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500



@app.route("/sms-logs", methods=["GET", "OPTIONS"])
def sms_logs():
    if request.method == "OPTIONS":
        return _ok_cors()
    try:
        auth_email = auth_from_token(request.headers.get("Authorization", "")) \
                     or (request.args.get("email") or request.headers.get("X-User-Email") or "").strip().lower()

        if not auth_email:
            # Same behavior as /calls – just return empty
            return jsonify([])

        viewer = find_user_by_email(auth_email)
        is_admin = False
        if viewer and str(viewer.get("role", "")).strip().lower() in {"admin", "administrator"}:
            is_admin = True

        rows = sms_ws.get_all_records()
        items = []
        for r in rows:
            row_email = (r.get("User Email") or r.get("user_email") or "").strip().lower()
            if is_admin or row_email == auth_email:
                items.append({
                    "created_at": r.get("Timestamp") or r.get("timestamp"),
                    "direction": r.get("Direction") or r.get("direction"),
                    "from_number": r.get("From") or r.get("from"),
                    "to_number": r.get("To") or r.get("to"),
                    "body": r.get("Body") or r.get("body"),
                    "status": r.get("Status") or r.get("status"),
                    "sid": r.get("SID") or r.get("sid")
                })

        items = list(reversed(items))
        return jsonify(items), 200
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500



@app.route("/sms-webhook", methods=["POST"])
def sms_webhook():
    """
    Twilio will POST here for inbound SMS.
    Set this as the Messaging webhook URL for your Twilio number.
    """
    try:
        from_raw = request.values.get("From") or ""
        to_raw = request.values.get("To") or request.values.get("ToNumber") or ""
        body = request.values.get("Body") or ""

        from_e164 = to_e164(from_raw)
        to_e164_num = to_e164(to_raw)

        user = find_user_by_assigned_number(to_e164_num)
        user_email = (user or {}).get("email") or ""

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        append_row_raw(
            sms_ws,
            [timestamp, "incoming", from_e164, to_e164_num, body, user_email, "received", ""]
        )

        print(f"[SMS INBOUND] from={from_e164} to={to_e164_num} user={user_email}")
    except Exception as e:
        print("sms-webhook error:", e)

    # We don't auto-reply, just 204 OK
    return ("", 204)


@app.route("/voicemails", methods=["GET", "OPTIONS"])
def get_voicemails():
    if request.method == "OPTIONS":
        return _ok_cors()
    try:
        auth_email = auth_from_token(request.headers.get("Authorization", "")) \
                     or (request.args.get("email") or request.headers.get("X-User-Email") or "").strip().lower()

        if not auth_email:
            # Same behavior as /calls and /sms-logs: return empty list for unauthenticated / no identity
            return jsonify([])

        viewer = find_user_by_email(auth_email)
        is_admin = False
        if viewer and str(viewer.get("role", "")).strip().lower() in {"admin", "administrator"}:
            is_admin = True

        rows = voicemails_ws.get_all_records()
        items = []

        for r in rows:
            row_email = (r.get("User Email") or r.get("user_email") or "").strip().lower()
            if is_admin or row_email == auth_email:
                items.append({
                    "created_at": r.get("Timestamp") or r.get("timestamp"),
                    "from_number": r.get("From") or r.get("from"),
                    "to_number": r.get("To") or r.get("to"),
                    "recording_url": r.get("RecordingUrl") or r.get("Recording URL") or r.get("recording_url"),
                    "duration": _coerce_int(
                        r.get("Duration") or
                        r.get("duration") or
                        r.get("RecordingDuration") or 0
                    ),
                })

        items = list(reversed(items))
        return jsonify(items), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500





@app.route("/vm-recording", methods=["POST"])
def vm_recording():
    """
    Recording status callback from Twilio <Record>.
    We store voicemail info into the Voicemails sheet.
    """
    try:
        data = request.values

        from_raw = data.get("From") or ""
        called_raw = data.get("Called") or data.get("To") or ""
        rec_url = data.get("RecordingUrl") or ""
        duration = _coerce_int(data.get("RecordingDuration"), 0)

        from_e164 = to_e164(from_raw)
        called_e164 = to_e164(called_raw)

        # Find which user owns the called number
        user = find_user_by_assigned_number(called_e164)
        user_email = (user or {}).get("email") or ""

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        # IMPORTANT: write ALL headers you have in Voicemails sheet:
        # Timestamp | From | To | RecordingUrl | Duration | User Email | Status
        append_row_raw(
            voicemails_ws,
            [timestamp, from_e164, called_e164, rec_url, duration, user_email, "new"]
        )

        print(
            f"[VM RECORDING] saved voicemail "
            f"from={from_e164} to={called_e164} user={user_email} url={rec_url}"
        )

    except Exception as e:
        print("vm-recording error:", e)

    return ("", 204)





# ---------------- Run ----------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
