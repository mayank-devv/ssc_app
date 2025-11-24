import streamlit as st
import gspread
from google.oauth2.service_account import Credentials
import hashlib
import pandas as pd
from datetime import datetime
import json

# -----------------------------------------------------------
# PAGE CONFIG
# -----------------------------------------------------------
st.set_page_config(
    page_title="SSC Workflow System",
    page_icon="📦",
    layout="wide"
)

# -----------------------------------------------------------
# PASSWORD HASHER
# -----------------------------------------------------------
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# -----------------------------------------------------------
# USER DATABASE (USERNAME → EMAIL + ROLE)
# -----------------------------------------------------------
USERS = {
    "siddarth": {
        "email": "siddarthagrawaal@gmail.com",
        "role": "admin",
        "password": hash_password("siddarth123")
    },
    "info": {
        "email": "ssc6.info@gmail.com",
        "role": "admin",
        "password": hash_password("info123")
    },
    "khyatee": {
        "email": "khyateeyagrawaal@gmail.com",
        "role": "multi",
        "password": hash_password("khyatee123")
    },
    "delivery": {
        "email": "deliveryperson.ssc@gmail.com",
        "role": "delivery",
        "password": hash_password("delivery123")
    },
    "payment": {
        "email": "paymentperson.ssc@gmail.com",
        "role": "payment",
        "password": hash_password("payment123")
    },
    "paymentp": {
        "email": "ssc6.payments@gmail.com",
        "role": "finance",
        "password": hash_password("paymentp123")
    }
}

# -----------------------------------------------------------
# LOGIN FUNCTION
# -----------------------------------------------------------
def login_screen():
    st.title("🔐 SSC Workflow Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    login_btn = st.button("Login")

    if login_btn:
        if username in USERS:
            hashed = hash_password(password)
            if hashed == USERS[username]["password"]:
                st.session_state["logged_in"] = True
                st.session_state["username"] = username
                st.session_state["role"] = USERS[username]["role"]
                st.experimental_rerun()
            else:
                st.error("Incorrect password.")
        else:
            st.error("Invalid username.")

# -----------------------------------------------------------
# LOGIN CHECK
# -----------------------------------------------------------
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False

if not st.session_state["logged_in"]:
    login_screen()
    st.stop()

st.success(f"Logged in as **{st.session_state['username']}** ({st.session_state['role']})")

# -----------------------------------------------------------
# COLUMN PERMISSION GROUPS (BASED ON YOUR MATRIX)
# -----------------------------------------------------------

ADMIN_COLUMNS = [
    "A","B","C","D","E","F","G","H","I","J",
    "L","N","O","Q","R","T","W","Z","AB","AD","AF","AH",
    "AJ","AM","AN","AO","AQ","AS","AU","AW","AX","AZ",
    "BA","BC","BD","BF","BG","BI","BK","BM"
]

DELIVERY_COLUMNS = ["V","X","Y","AA","AE","AG","AI","AK","AL"]

PAYMENT_COLUMNS = ["AP","AR","AT","AV","AY","BB","BE","BH","BJ","BL","BN","BO","BP","BQ"]

FINANCE_COLUMNS = ["M","P","S","U"]

KHYATEE_ONLY = ["K","AC"]

# -----------------------------------------------------------
# ROLE → COLUMN PERMISSION
# -----------------------------------------------------------
ROLE_PERMISSIONS = {
    "admin": ADMIN_COLUMNS + DELIVERY_COLUMNS + PAYMENT_COLUMNS + FINANCE_COLUMNS + KHYATEE_ONLY,
    "delivery": DELIVERY_COLUMNS,
    "payment": PAYMENT_COLUMNS,
    "finance": FINANCE_COLUMNS,
    "multi": DELIVERY_COLUMNS + PAYMENT_COLUMNS + FINANCE_COLUMNS + KHYATEE_ONLY
}

# -----------------------------------------------------------
# GOOGLE SHEETS CONNECTION
# -----------------------------------------------------------

SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive"
]

creds = Credentials.from_service_account_info(
    st.secrets["gcp_service_account"],
    scopes=SCOPES
)

client = gspread.authorize(creds)

WORKBOOK_NAME = "SSC Workflow Main DB"

# -----------------------------------------------------------
# LOAD SHEET DROPDOWN
# -----------------------------------------------------------
st.subheader("📄 Select Brand Sheet")
SHEET_NAMES = ["GODREJ", "LG", "WHIRLPOOL", "UNILINE", "LLOYD"]

selected_sheet = st.selectbox("Choose a sheet:", SHEET_NAMES)
sheet = client.open(WORKBOOK_NAME).worksheet(selected_sheet)

# -----------------------------------------------------------
# LOAD DATAFRAME
# -----------------------------------------------------------
data = sheet.get_all_records()
df = pd.DataFrame(data)
original_df = df.copy()

# -----------------------------------------------------------
# HELPERS
# -----------------------------------------------------------
def col_letter(idx):
    return chr(ord('A') + idx)

# -----------------------------------------------------------
# DETERMINE EDITABLE COLS
# -----------------------------------------------------------

user_role = st.session_state["role"]
allowed_cols = ROLE_PERMISSIONS[user_role]

editable_columns = []
for i, col in enumerate(df.columns):
    letter = col_letter(i)
    if letter in allowed_cols or user_role == "admin":
        editable_columns.append(col)

# -----------------------------------------------------------
# LOCK SHEET
# -----------------------------------------------------------
LOCK_SHEET_NAME = "LOCKS"

try:
    lock_sheet = client.open(WORKBOOK_NAME).worksheet(LOCK_SHEET_NAME)
except:
    client.open(WORKBOOK_NAME).add_worksheet(LOCK_SHEET_NAME, rows=5000, cols=10)
    lock_sheet = client.open(WORKBOOK_NAME).worksheet(LOCK_SHEET_NAME)
    lock_sheet.append_row(["sheet", "row", "column", "locked"])

lock_data = lock_sheet.get_all_records()
lock_df = pd.DataFrame(lock_data)

def is_cell_locked(sheet_name, row, col_l):
    if lock_df.empty:
        return False
    q = lock_df[
        (lock_df["sheet"] == sheet_name) &
        (lock_df["row"] == row) &
        (lock_df["column"] == col_l) &
        (lock_df["locked"] == "yes")
    ]
    return not q.empty

# -----------------------------------------------------------
# FILTER FINAL EDITABLE COLUMNS
# -----------------------------------------------------------
final_editable_cols = []
for i, col in enumerate(df.columns):
    letter = col_letter(i)

    if col not in editable_columns:
        continue

    locked_rows = []
    for r in range(len(df)):
        if original_df.iloc[r, i] not in ["", None, " ", "nan"]:
            locked_rows.append(r)
        if is_cell_locked(selected_sheet, r+2, letter):
            locked_rows.append(r)

    if len(locked_rows) != len(df):
        final_editable_cols.append(col)

# -----------------------------------------------------------
# EDITOR
# -----------------------------------------------------------
st.subheader("📋 Editable Table")

edited_df = st.data_editor(
    df,
    use_container_width=True,
    disabled=[c for c in df.columns if c not in final_editable_cols]
)
# -----------------------------------------------------------
# DETECT CHANGES
# -----------------------------------------------------------
changes = []

for r in range(len(df)):
    for c, col_name in enumerate(df.columns):
        old = original_df.iloc[r, c]
        new = edited_df.iloc[r, c]

        if str(old) != str(new):
            col_l = col_letter(c)

            # Permission check
            if col_name not in final_editable_cols:
                st.error(f"❌ Permission denied for column {col_name} ({col_l})")
                st.stop()

            # Lock check
            if is_cell_locked(selected_sheet, r+2, col_l):
                st.error(f"❌ Cell already locked: Row {r+2}, Col {col_l}")
                st.stop()

            changes.append({
                "row": r + 2,
                "column": col_l,
                "old": old,
                "new": new
            })

# -----------------------------------------------------------
# LOG SHEET
# -----------------------------------------------------------
LOG_SHEET_NAME = "LOGS"

try:
    log_sheet = client.open(WORKBOOK_NAME).worksheet(LOG_SHEET_NAME)
except:
    client.open(WORKBOOK_NAME).add_worksheet(LOG_SHEET_NAME, rows=5000, cols=10)
    log_sheet = client.open(WORKBOOK_NAME).worksheet(LOG_SHEET_NAME)
    log_sheet.append_row([
        "timestamp","user","sheet","row","column","old_value","new_value"
    ])

# -----------------------------------------------------------
# SAVE BLOCK
# -----------------------------------------------------------
st.markdown("---")
st.subheader("💾 Save Changes")

if changes:
    st.write("Changes detected:")
    st.dataframe(pd.DataFrame(changes))

    if st.button("✅ Save changes to Google Sheets"):
        for ch in changes:
            row = ch["row"]
            col_l = ch["column"]
            new = ch["new"]
            old = ch["old"]

            # Convert letter → index
            col_idx = ord(col_l) - ord("A") + 1

            # Update Google Sheet
            sheet.update_cell(row, col_idx, "" if new is None else str(new))

            # Lock the cell
            lock_sheet.append_row([
                selected_sheet,
                row,
                col_l,
                "yes"
            ])

            # Log the event
            log_sheet.append_row([
                datetime.now().isoformat(timespec="seconds"),
                st.session_state["username"],
                selected_sheet,
                row,
                col_l,
                "" if old is None else str(old),
                "" if new is None else str(new)
            ])

        st.success("✅ Changes saved, locked, and logged.")
        st.experimental_rerun()

else:
    st.info("No changes detected.")

# -----------------------------------------------------------
# ADMIN UNLOCK PANEL
# -----------------------------------------------------------
st.markdown("---")
if st.session_state["role"] == "admin":
    st.subheader("🔓 Admin Unlock Cell")

    unlock_sheet = st.selectbox("Sheet:", SHEET_NAMES)
    unlock_row = st.number_input("Row number", min_value=2, step=1)
    unlock_col = st.text_input("Column letter", max_chars=3).upper().strip()

    if st.button("Unlock"):
        all_locks = lock_sheet.get_all_values()

        if len(all_locks) <= 1:
            st.warning("No locks found.")
        else:
            headers = all_locks[0]
            new_values = [headers]
            removed = False

            for rowvals in all_locks[1:]:
                d = dict(zip(headers, rowvals))

                # Match
                if (
                    d["sheet"] == unlock_sheet and
                    d["row"] == str(int(unlock_row)) and
                    d["column"] == unlock_col and
                    d["locked"] == "yes"
                ):
                    removed = True
                    continue

                new_values.append(rowvals)

            if removed:
                lock_sheet.clear()
                lock_sheet.update("A1", new_values)
                st.success(f"Unlocked {unlock_sheet}! R{int(unlock_row)}C{unlock_col}")
                st.experimental_rerun()
            else:
                st.warning("No matching lock found.")

else:
    st.info("Admin-only panel.")
