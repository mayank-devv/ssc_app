import streamlit as st
import gspread
from google.oauth2.service_account import Credentials
import hashlib
import pandas as pd
from datetime import datetime

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
# USER LOGIN DATABASE
# -----------------------------------------------------------
USERS = {
    "siddarth": {
        "email": "siddarthagrawaal@gmail.com",
        "role": "siddarth",
        "password": hash_password("siddarth123")
    },
    "info": {
        "email": "ssc6.info@gmail.com",
        "role": "siddarth",
        "password": hash_password("info123")
    },
    "delivery": {
        "email": "deliveryperson.ssc@gmail.com",
        "role": "delivery",
        "password": hash_password("delivery123")
    },
    "payment1": {
        "email": "paymentperson.ssc@gmail.com",
        "role": "payment1",
        "password": hash_password("payment1123")
    },
    "payment2": {
        "email": "ssc6.payments@gmail.com",
        "role": "payment2",
        "password": hash_password("payment2123")
    },
    "khyatee": {
        "email": "khyateeyagrawaal@gmail.com",
        "role": "khyatee",
        "password": hash_password("khyatee123")
    },
    "mayank": {
        "email": "mayank@gmail.com",
        "role": "mayank",
        "password": hash_password("mayank123")
    },
    "shrish": {
        "email": "shrish@gmail.com",
        "role": "shrish",
        "password": hash_password("shrish123")
    }
}

# -----------------------------------------------------------
# ROLE PERMISSIONS (NEW RULES ONLY)
# -----------------------------------------------------------
ROLE_PERMISSIONS = {

    "siddarth": [
        "A","B","C","D","E","I","K","L","M","O","Q","S","V","Y",
        "AC","AE","AG","AI","AL","AN","AP","AR","AT","AU",
        "AW","AX","AZ","BA","BC","BD","BF","BG","BI"
    ],

    "delivery": [
        "F","G","H","U","W","X","Z","AD","AF","AH","AJ","AK"
    ],

    "khyatee": [
        "J","N","P","R","AA","AB","BJ","BK"
    ],

    "payment1": [
        "T","AM","AS","AV","AY","BB","BE","BH"
    ],

    "payment2": [
        "T","AM","AS","AV","AY","BB","BE","BH"
    ],

    "mayank": [
        "AO","AQ"
    ],

    "shrish": [
        "BL","BM"
    ]
}

# -----------------------------------------------------------
# LOGIN SCREEN
# -----------------------------------------------------------
def login_screen():
    st.title("🔐 SSC Workflow Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    login_btn = st.button("Login")

    if login_btn:
        if username in USERS:
            if hash_password(password) == USERS[username]["password"]:
                st.session_state["logged_in"] = True
                st.session_state["username"] = username
                st.session_state["role"] = USERS[username]["role"]
                st.experimental_rerun()
            else:
                st.error("Incorrect password.")
        else:
            st.error("Invalid username.")

if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False

if not st.session_state["logged_in"]:
    login_screen()
    st.stop()

st.success(f"Logged in as **{st.session_state['username']}** ({st.session_state['role']})")

# -----------------------------------------------------------
# GOOGLE SHEETS SETUP
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
# SHEET DROPDOWN
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
# COLUMN LETTER FUNCTION
# -----------------------------------------------------------
def col_letter(idx):
    return chr(ord('A') + idx)

# -----------------------------------------------------------
# BUILD EDIT PERMISSIONS
# -----------------------------------------------------------
role = st.session_state["role"]
allowed_columns = ROLE_PERMISSIONS.get(role, [])

editable_cols = []

for i, col in enumerate(df.columns):
    if col_letter(i) in allowed_columns:
        editable_cols.append(col)

st.subheader("📋 Editable Table")

edited_df = st.data_editor(
    df,
    use_container_width=True,
    disabled=[c for c in df.columns if c not in editable_cols]
)

# detect changes
changes = []

for r in range(len(df)):
    for c in range(len(df.columns)):
        old = original_df.iloc[r, c]
        new = edited_df.iloc[r, c]
        if old != new:
            changes.append({
                "row": r + 2,
                "column": col_letter(c),
                "old": old,
                "new": new
            })
# -----------------------------------------------------------
# LOCK SHEET
# -----------------------------------------------------------
LOCK_SHEET_NAME = "LOCKS"

# Ensure lock sheet exists
try:
    lock_sheet = client.open(WORKBOOK_NAME).worksheet(LOCK_SHEET_NAME)
except:
    client.open(WORKBOOK_NAME).add_worksheet(LOCK_SHEET_NAME, rows=5000, cols=10)
    lock_sheet = client.open(WORKBOOK_NAME).worksheet(LOCK_SHEET_NAME)
    lock_sheet.append_row(["sheet", "row", "column", "locked"])


# reload lock data
lock_data = lock_sheet.get_all_records()
lock_df = pd.DataFrame(lock_data)

def is_cell_locked(sheet_name, row, col_letter):
    if lock_df.empty:
        return False
    match = lock_df[
        (lock_df["sheet"] == sheet_name) &
        (lock_df["row"] == row) &
        (lock_df["column"] == col_letter) &
        (lock_df["locked"] == "yes")
    ]
    return not match.empty

# -----------------------------------------------------------
# CHECK LOCKS + PERMISSIONS
# -----------------------------------------------------------
final_editable_cols = []

for i, col in enumerate(df.columns):
    letter = col_letter(i)

    # user can't edit if column letter not in role permissions
    if letter not in allowed_columns:
        continue

    # check if entire column locked
    unlocked_found = False
    for r in range(len(df)):
        if not is_cell_locked(selected_sheet, r+2, letter):
            unlocked_found = True
            break

    if unlocked_found:
        final_editable_cols.append(col)


st.subheader("📋 Editable Table (With Auto-Locking)")
edited_df = st.data_editor(
    df,
    use_container_width=True,
    disabled=[c for c in df.columns if c not in final_editable_cols]
)

# -----------------------------------------------------------
# DETECT CHANGES WITH LOCK + PERMISSION CHECK
# -----------------------------------------------------------
changes = []

for r in range(len(df)):
    for c, col_name in enumerate(df.columns):

        old = original_df.iloc[r, c]
        new = edited_df.iloc[r, c]

        if old != new:
            col_l = col_letter(c)

            # block if locked
            if is_cell_locked(selected_sheet, r+2, col_l):
                st.error(f"❌ Cell locked: Row {r+2}, Col {col_l}")
                st.stop()

            # block if not allowed
            if col_l not in allowed_columns:
                st.error(f"❌ You do not have permission for Column {col_l}")
                st.stop()

            changes.append({
                "row": r + 2,
                "column": col_l,
                "old": old,
                "new": new
            })


# -----------------------------------------------------------
# LOG SHEET SETUP
# -----------------------------------------------------------
LOG_SHEET_NAME = "LOGS"

try:
    log_sheet = client.open(WORKBOOK_NAME).worksheet(LOG_SHEET_NAME)
except:
    client.open(WORKBOOK_NAME).add_worksheet(LOG_SHEET_NAME, rows=5000, cols=20)
    log_sheet = client.open(WORKBOOK_NAME).worksheet(LOG_SHEET_NAME)
    log_sheet.append_row(["timestamp", "user", "sheet", "row", "column", "old_value", "new_value"])


# -----------------------------------------------------------
# SAVE CHANGES BUTTON + APPLY LOCKS
# -----------------------------------------------------------
st.markdown("---")
st.subheader("💾 Save Changes")

if changes:
    st.write("Changes detected:")
    st.dataframe(pd.DataFrame(changes))

    if st.button("✅ Save now"):
        for change in changes:
            row = change["row"]
            col = change["column"]
            old_val = change["old"]
            new_val = change["new"]

            col_index = ord(col) - ord('A') + 1

            # update in sheet
            sheet.update_cell(row, col_index, "" if pd.isna(new_val) else str(new_val))

            # lock cell
            lock_sheet.append_row([selected_sheet, row, col, "yes"])

            # log change
            log_sheet.append_row([
                datetime.now().isoformat(timespec="seconds"),
                st.session_state["username"],
                selected_sheet,
                row,
                col,
                "" if pd.isna(old_val) else str(old_val),
                "" if pd.isna(new_val) else str(new_val)
            ])

        st.success("✔ Saved, ✔ Locked, ✔ Logged")
        st.experimental_rerun()
else:
    st.info("No changes detected.")

# -----------------------------------------------------------
# ADMIN UNLOCK PANEL
# -----------------------------------------------------------
st.markdown("---")
st.subheader("🔓 Admin Unlock (only Siddarth / Info)")

if st.session_state["role"] != "siddarth":
    st.info("Only Siddarth/Info can unlock.")
    st.stop()

unlock_sheet = st.selectbox("Sheet:", SHEET_NAMES)
unlock_row = st.number_input("Row number", min_value=2, step=1)
unlock_col = st.text_input("Column letter (A, B, C...)").upper().strip()

if st.button("Unlock Now"):
    all_locks = lock_sheet.get_all_values()

    if len(all_locks) <= 1:
        st.warning("No locks exist.")
    else:
        headers = all_locks[0]
        new_rows = [headers]
        removed = False

        for row_data in all_locks[1:]:
            row_dict = dict(zip(headers, row_data))

            if (row_dict["sheet"] == unlock_sheet and
                str(row_dict["row"]) == str(int(unlock_row)) and
                row_dict["column"] == unlock_col):
                removed = True
                continue

            new_rows.append(row_data)

        lock_sheet.clear()
        lock_sheet.update("A1", new_rows)

        if removed:
            st.success(f"Unlocked {unlock_sheet} → Row {unlock_row}, Col {unlock_col}")
            st.experimental_rerun()
        else:
            st.error("Lock not found.")
