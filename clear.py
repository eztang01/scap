"""
Author: Eric Tang
Date: 11/28/2021
SCAP Project

This program clears Google Spreadsheet.
"""

import gspread
from oauth2client.service_account import ServiceAccountCredentials

scope = ["https://spreadsheets.google.com/feeds",'https://www.googleapis.com/auth/spreadsheets',"https://www.googleapis.com/auth/drive.file","https://www.googleapis.com/auth/drive"]

creds = ServiceAccountCredentials.from_json_keyfile_name("credentials.json", scope)
client = gspread.authorize(creds)

clear_nvd = False
clear_nipc = True

if clear_nvd:
    sheet = client.open("SCAP").worksheet("nvd_type")
    sheet.clear()  
    sheet = client.open("SCAP").worksheet("nvd_data")
    sheet.clear()  
    sheet = client.open("SCAP").worksheet("nvd_date")
    sheet.clear()  

if clear_nipc:
    sheet = client.open("SCAP").worksheet("nipc_type")
    sheet.clear()   
    sheet = client.open("SCAP").worksheet("nipc_data")
    sheet.clear()   