from flask import Flask, request, jsonify
from google.oauth2.service_account import Credentials
import gspread
import os
from flask_cors import CORS

# ---------------------------
# Flask App Setup
# ---------------------------
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  # ✅ add this line

@app.route("/")
def home():
    return jsonify({"message": "Backend is running!"})


# ---------------------------
# Google Sheets Setup
# ---------------------------

# Load credentials from your JSON file
# (On Render, we’ll upload this as a Secret File named 'credentials.json')
creds = Credentials.from_service_account_file(
    "credentials.json",
    scopes=["https://www.googleapis.com/auth/spreadsheets"]
)
gc = gspread.authorize(creds)

# Use environment variable for Sheet URL
SHEET_URL = os.environ.get(
    "GOOGLE_SHEET_URL",
    "https://docs.google.com/spreadsheets/d/YOUR_SHEET_ID_HERE/edit"
)
sh = gc.open_by_url(SHEET_URL)

# Access tabs
users_ws = sh.worksheet("Users")
calls_ws = sh.worksheet("CallLogs")

# ---------------------------
# Routes
# ---------------------------

@app.route("/login", methods=["POST"])
def login():
    """Authenticate user from Google Sheets."""
    data = request.json
    email = data.get("email")
    password = data.get("password")

    users = users_ws.get_all_records()

    for user in users:
        if user.get("Email") == email and user.get("Password") == password:
            # ✅ Updated structure for frontend compatibility
            return jsonify({
                "token": "dummy-token-123",  # temporary until we add JWT
                "user": {
                    "email": email,
                    "display_name": user.get("Display Name"),
                    "assigned_number": user.get("Assigned Number"),
                    "expiry_date": user.get("Expiry Date"),
                    "role": user.get("Role"),
                }
            })

    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/profile", methods=["GET"])
def profile():
    """Return user profile info by email (from Google Sheets)."""
    email = request.args.get("email")  # get ?email=... from URL

    if not email:
        return jsonify({"error": "Missing email"}), 400

    users = users_ws.get_all_records()

    for user in users:
        if user.get("Email") == email:
            return jsonify({
                "email": user.get("Email"),
                "display_name": user.get("Display Name"),
                "assigned_number": user.get("Assigned Number"),
                "expiry_date": user.get("Expiry Date"),
                "role": user.get("Role")
            })

    return jsonify({"error": "User not found"}), 404



# ---------------------------
# Run the app
# ---------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
