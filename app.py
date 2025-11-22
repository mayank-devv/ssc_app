import os
os.environ["TZ"] = "UTC"
import streamlit as st
import gspread
from google.oauth2.service_account import Credentials

st.title("SSC Workflow Test App")

# Setup Google Sheets API
scope = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive"
]

creds = Credentials.from_service_account_info(
    st.secrets["gcp_service_account"], scopes=scope)
client = gspread.authorize(creds)

# Try to open a sheet
st.write("Connecting to Google Sheets...")

try:
    sheet = client.open("SSC Workflow Main DB").sheet1
    st.success("Connected successfully!")
    
    data = sheet.get_all_records()
    st.write("Sheet Data:")
    st.write(data)

except Exception as e:
    st.error("Error connecting to Google Sheet")
    st.error(e)

