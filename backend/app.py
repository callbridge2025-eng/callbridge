from flask import Flask, request, jsonify
from google.oauth2.service_account import Credentials
import gspread
import os

# ---------------------------
# Flask App Setup
# ---------------------------
app = Flask(__name__)

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
            return jsonify({
                "success": True,
                "email": email,
                "display_name": user.get("Display Name"),
                "assigned_number": user.get("Assigned Number"),
                "expiry_date": user.get("Expiry Date"),
                "role": user.get("Role")
            })

    return jsonify({"success": False, "error": "Invalid credentials"}), 401


# ---------------------------
# Run the app
# ---------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
