from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import os, time, traceback, json, tempfile
import phonenumbers

# Firebase Admin / Firestore
import firebase_admin
from firebase_admin import credentials, auth, firestore

# Twilio (kept during Phase 1)
from twilio.jwt.access_token import AccessToken
from twilio.jwt.access_token.grants import VoiceGrant
from twilio.twiml.voice_response import VoiceResponse, Dial

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
print("FIREBASE_PROJECT_ID:", os.getenv("FIREBASE_PROJECT_ID"))
print("HAS_JSON_ENV:", bool(os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON")))
print("HAS_FILE_PATH:", bool(os.getenv("GOOGLE_APPLICATION_CREDENTIALS")))

@app.get("/health")
def health():
    return {"status": "ok"}
@app.before_request
def init_firebase_once():
    if request.method != "OPTIONS" and request.path != "/health":
        ensure_firebase()


# ---------- Firebase Admin lazy init ----------
firebase_inited = False
db = None

def ensure_firebase():
    global firebase_inited, db
    if firebase_inited:
        return

    try:
        cred = None
        creds_json = os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON")
        creds_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")  # Secret File path
        if creds_json:
            data = json.loads(creds_json)
            with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
                tmp.write(json.dumps(data).encode()); tmp.flush()
                cred = credentials.Certificate(tmp.name)
        elif creds_path and os.path.exists(creds_path):
            cred = credentials.Certificate(creds_path)
        else:
            raise RuntimeError("Firebase creds missing: set GOOGLE_APPLICATION_CREDENTIALS_JSON or GOOGLE_APPLICATION_CREDENTIALS")

        if not firebase_admin._apps:
            firebase_admin.initialize_app(cred, {"projectId": os.getenv("FIREBASE_PROJECT_ID")})

        # init Firestore client
        globals()["db"] = firestore.client()
        firebase_inited = True
        print("✅ Firebase initialized")
    except Exception as e:
        print("🔥 Firebase init failed:", repr(e))
        traceback.print_exc()
        # don't raise here; let routes return a friendly error instead


# ---------- Helpers ----------
def _ok_cors():
    resp = make_response("", 200)
    h = resp.headers
    h["Access-Control-Allow-Origin"] = "*"
    h["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    h["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    return resp

def to_e164(num: str, default_region='US') -> str:
    if not num: return num
    n = str(num).strip()
    try:
        if n.isdigit() and len(n)==10 and default_region=='US':
            n = f"+1{n}"
        p = phonenumbers.parse(n, default_region)
        if phonenumbers.is_valid_number(p):
            return phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.E164)
    except Exception:
        pass
    return n

def require_user(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        authz = request.headers.get("Authorization", "")
        if not authz.startswith("Bearer "):
            return jsonify({"error":"Missing ID token"}), 401
        id_token = authz.split(" ",1)[1].strip()
        try:
            decoded = auth.verify_id_token(id_token)
            request.user = decoded  # uid, email, email_verified, etc.
        except Exception:
            return jsonify({"error":"Invalid or expired ID token"}), 401
        if not request.user.get("email_verified", False):
            return jsonify({"error":"Email not verified"}), 403
        return f(*args, **kwargs)
    return wrapper

def get_user_doc_by_email(email):
    if not email: return None
    q = db.collection("users").where("email_lower","==", email.strip().lower()).limit(1).stream()
    for doc in q: return doc.to_dict()
    return None

def get_user_by_assigned_number(e164):
    q = db.collection("users").where("assigned_number","==", e164).limit(1).stream()
    for doc in q: return doc.to_dict()
    return None

def _https_url(url, req):
    proto = req.headers.get("X-Forwarded-Proto", "https")
    if url.startswith("http://") and proto == "https":
        return "https://" + url[len("http://"):]
    return url

@app.before_request
def preflight():
    if request.method == "OPTIONS":
        return _ok_cors()

@app.after_request
def after(response):
    h = response.headers
    h["Access-Control-Allow-Origin"] = "*"
    h["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    h["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    return response

# ---------- Routes ----------
@app.get("/")
def home():
    return jsonify({"message":"Backend is running with Firebase/Firestore"})

# Profile by email (used by your frontend)
@app.post("/profile")
def profile():
    try:
        data = request.get_json(force=True) if request.is_json else {}
        email = (data or {}).get("email")
        if not email:
            return jsonify({"error":"email required"}), 400
        user = get_user_doc_by_email(email)
        if not user:
            return jsonify({"error":"User not found"}), 404
        out = {
            "id": user.get("email"),
            "email": user.get("email"),
            "display_name": user.get("display_name") or user.get("name"),
            "assigned_number": user.get("assigned_number"),
            "expiry_date": user.get("expiry_date"),
            "role": user.get("role","user"),
        }
        return jsonify(out)
    except Exception:
        traceback.print_exc()
        return jsonify({"error":"Internal server error"}), 500

@app.get("/")
def home():
    if not firebase_inited:
        return jsonify({"error":"Firebase not initialized (check credentials envs)"}), 500
    return jsonify({"message":"Backend is running with Firebase/Firestore"})

@app.post("/profile")
def profile():
    if not firebase_inited:
        return jsonify({"error":"Firebase not initialized (check credentials envs)"}), 500
    try:
        data = request.get_json(force=True) if request.is_json else {}
        ...

@app.get("/calls")
@require_user
def get_calls():
    if not firebase_inited:
        return jsonify({"error":"Firebase not initialized (check credentials envs)"}), 500
    try:
        ...

@app.post("/save-call")
@require_user
def save_call():
    if not firebase_inited:
        return jsonify({"error":"Firebase not initialized (check credentials envs)"}), 500
    try:
        ...

@app.post("/twilio-token")
@require_user
def twilio_token():
    if not firebase_inited:
        return jsonify({"error":"Firebase not initialized (check credentials envs)"}), 500
    try:
        ...

@app.post("/voice")
def voice():
    if not firebase_inited:
        return str(VoiceResponse()), 500, {"Content-Type": "application/xml"}
    try:
        ...

@app.post("/client-status")
def client_status():
    if not firebase_inited:
        return ("", 204)
    try:
        ...

@app.post("/dial-action")
def dial_action():
    if not firebase_inited:
        return str(VoiceResponse()), 200, {"Content-Type":"application/xml"}
    try:
        ...

@app.post("/vm-screen")
def vm_screen():
    if not firebase_inited:
        return str(VoiceResponse()), 200, {"Content-Type":"application/xml"}
    try:
        ...


# Calls history (now reads Firestore)
@app.get("/calls")
@require_user
def get_calls():
    try:
        viewer_email = (request.user.get("email") or "").strip().lower()
        viewer = get_user_doc_by_email(viewer_email)
        is_admin = (viewer or {}).get("role","").lower() in {"admin","administrator"}

        calls_ref = db.collection("call_logs").order_by("created_at", direction=firestore.Query.DESCENDING).limit(500)
        items = []
        for doc in calls_ref.stream():
            r = doc.to_dict()
            if is_admin or (r.get("user_email","").strip().lower()==viewer_email):
                items.append({
                    "created_at": r.get("created_at"),
                    "from_number": r.get("from_number"),
                    "to_number": r.get("to_number"),
                    "duration": r.get("duration",0),
                    "user_email": r.get("user_email"),
                    "call_type": r.get("call_type"),
                    "status": r.get("status"),
                })
        return jsonify(items)
    except Exception:
        traceback.print_exc()
        return jsonify({"error":"Internal server error"}), 500

@app.post("/save-call")
@require_user
def save_call():
    try:
        data = request.get_json(force=True)
        ts = data.get("created_at") or firestore.SERVER_TIMESTAMP
        from_num = to_e164(data.get("from") or data.get("from_number") or "", 'US')
        to_num   = to_e164(data.get("to") or data.get("to_number") or "", 'US')
        duration = int(data.get("duration") or 0)
        call_type = data.get("call_type") or ""
        status = data.get("status") or data.get("notes") or ""
        user_email = (request.user.get("email") or data.get("user_email") or "").strip().lower()

        db.collection("call_logs").add({
            "created_at": ts,
            "from_number": from_num,
            "to_number": to_num,
            "duration": duration,
            "user_email": user_email,
            "call_type": call_type,
            "status": status,
        })
        return jsonify({"success": True})
    except Exception:
        traceback.print_exc()
        return jsonify({"error":"Internal server error"}), 500

# Twilio token now requires Firebase auth
@app.post("/twilio-token")
@require_user
def twilio_token():
    try:
        ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
        API_KEY_SID = os.getenv("TWILIO_API_KEY_SID")
        API_KEY_SECRET = os.getenv("TWILIO_API_KEY_SECRET")
        TWIML_APP_SID = os.getenv("TWILIO_TWIML_APP_SID")
        if not (ACCOUNT_SID and API_KEY_SID and API_KEY_SECRET and TWIML_APP_SID):
            return jsonify({"error":"Twilio configuration missing"}), 500

        identity = request.user.get("email")
        token = AccessToken(ACCOUNT_SID, API_KEY_SID, API_KEY_SECRET, identity=str(identity))
        voice_grant = VoiceGrant(outgoing_application_sid=TWIML_APP_SID, incoming_allow=True)
        token.add_grant(voice_grant)
        jwt_bytes = token.to_jwt()
        jwt = jwt_bytes.decode("utf-8") if isinstance(jwt_bytes, bytes) else jwt_bytes

        user_doc = get_user_doc_by_email(identity)
        raw_caller = (user_doc or {}).get("assigned_number") or os.getenv("TWILIO_PHONE_NUMBER")
        caller_id = to_e164(raw_caller, 'US')

        return jsonify({"token": jwt, "callerId": caller_id})
    except Exception:
        traceback.print_exc()
        return jsonify({"error":"Internal server error"}), 500

# ----- Twilio Webhooks (unchanged logic; Firestore-backed lookups) -----
@app.post("/voice")
def voice():
    try:
        from_param = request.values.get("From","") or ""
        is_client_call = from_param.startswith("client:")
        default_caller_id = os.getenv("TWILIO_CALLER_ID") or os.getenv("TWILIO_PHONE_NUMBER")
        resp = VoiceResponse()

        if is_client_call:
            outbound_to = request.values.get("To","") or ""
            requested_caller = request.values.get("CallerId","") or ""
            identity = from_param.split(":",1)[1] if ":" in from_param else ""
            user = get_user_doc_by_email(identity) if identity else None
            user_assigned = (user or {}).get("assigned_number")

            caller_id = to_e164(requested_caller or user_assigned or default_caller_id, 'US')
            outbound_to = to_e164(outbound_to, 'US')

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
            called_raw = request.values.get("Called") or request.values.get("To") or ""
            caller_raw = request.values.get("Caller") or request.values.get("From") or ""
            called_e164 = to_e164(called_raw, 'US')
            caller_e164 = to_e164(caller_raw, 'US')

            target_user = get_user_by_assigned_number(called_e164)
            if not target_user or not target_user.get("email"):
                resp.say("We could not find a destination for this call. Goodbye.")
                return str(resp), 200, {"Content-Type": "application/xml"}

            identity = str(target_user["email"]).strip()
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

@app.post("/client-status")
def client_status():
    try:
        data = request.values.to_dict()
        call_status = (data.get("CallStatus") or "").lower()
        dial_call_status = (data.get("DialCallStatus") or "").lower()
        from_number_raw = data.get("From") or ""
        to_raw = data.get("To") or data.get("Called") or ""
        identity = to_raw.split(":",1)[1] if to_raw.startswith("client:") else to_raw

        if call_status == "completed" and dial_call_status in {"no-answer","busy","failed"}:
            user_email = ""
            assigned_e164 = ""
            if identity:
                u = get_user_doc_by_email(identity)
                if u:
                    user_email = u.get("email") or ""
                    assigned_e164 = to_e164(u.get("assigned_number") or "", "US")

            from_e164 = to_e164(from_number_raw, "US")
            to_e164_num = assigned_e164 or to_e164(to_raw, "US")

            db.collection("call_logs").add({
                "created_at": firestore.SERVER_TIMESTAMP,
                "from_number": from_e164,
                "to_number": to_e164_num,
                "duration": 0,
                "user_email": user_email,
                "call_type": "incoming",
                "status": f"Missed ({dial_call_status})",
            })
        return ("", 204)
    except Exception as e:
        print("client-status error:", e)
        return ("", 204)

@app.post("/dial-action")
def dial_action():
    try:
        data = request.values.to_dict()
        dial_status = (data.get("DialCallStatus") or "").lower()
        if dial_status not in {"no-answer","busy","failed"}:
            return str(VoiceResponse()), 200, {"Content-Type":"application/xml"}

        from_e164 = to_e164(data.get("From") or "", "US")
        called_e164 = to_e164(data.get("Called") or data.get("To") or "", "US")
        user = get_user_by_assigned_number(called_e164)
        user_email = (user or {}).get("email") or ""

        db.collection("call_logs").add({
            "created_at": firestore.SERVER_TIMESTAMP,
            "from_number": from_e164,
            "to_number": called_e164,
            "duration": 0,
            "user_email": user_email,
            "call_type": "incoming",
            "status": f"Missed ({dial_status})",
        })
        return str(VoiceResponse()), 200, {"Content-Type":"application/xml"}
    except Exception as e:
        print("dial-action error:", e)
        return str(VoiceResponse()), 200, {"Content-Type":"application/xml"}

@app.post("/vm-screen")
def vm_screen():
    try:
        answered_by = (request.values.get("AnsweredBy") or "").lower()
        vr = VoiceResponse()
        if answered_by.startswith("machine_end_") or answered_by.startswith("machine"):
            vr.pause(length=1)
            return str(vr), 200, {"Content-Type": "application/xml"}
        return str(vr), 200, {"Content-Type": "application/xml"}
    except Exception as e:
        print("vm-screen error:", e)
        return str(VoiceResponse()), 200, {"Content-Type": "application/xml"}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
