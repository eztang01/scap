"""
Author: Eric Tang
Date: 11/21/2021
SCAP Project

This program has helper functions to write vulnerabilities into a Google Spreadsheet.
"""

import gspread
import numpy as np
from oauth2client.service_account import ServiceAccountCredentials

# opens up worksheet "SCAP"
scope = ["https://spreadsheets.google.com/feeds",'https://www.googleapis.com/auth/spreadsheets',"https://www.googleapis.com/auth/drive.file","https://www.googleapis.com/auth/drive"]
creds = ServiceAccountCredentials.from_json_keyfile_name("credentials.json", scope)
client = gspread.authorize(creds)
sheet = client.open("SCAP")


"""
parameters:
    name - string
    gheader - string
returns all values in a given sheet
if gheader exists, return column with header name
"""
def get_values(name, gheader = ""):
    if gheader:
        col_num = (sheet.worksheet(name).get_all_values()[0]).index(gheader)
        return sheet.worksheet(name).col_values(col_num + 1)
    return sheet.worksheet(name).get_all_values()
"""
parameters:
    name - list
returns all headers in name list
"""
def get_headers(name):
    name_list = []
    for item in name:
        try:
            name_list = name_list + (sheet.worksheet(item).get_all_values()[0])
        except:
            print("Invalid sheet name.")
    return name_list


"""________________________________________________________________________________________________________________________________
UPDATER FUNCTIONS
Used for when there are values in the spreadsheet
"""

def update_nvd(values):

    y = len(get_values("nvd_type")) + 1

    sheet.worksheet('nvd_type').add_rows(len(values))  
    sheet.worksheet('nvd_data').add_rows(len(values))  
    sheet.worksheet('nvd_date').add_rows(len(values))  

    sheet.values_update('nvd_type!A' + str(y), params={'valueInputOption': 'RAW'}, body={'values': split(values[0:len(values)], 0, 10)})  
    sheet.values_update('nvd_data!A' + str(y), params={'valueInputOption': 'RAW'}, body={'values': split(values[0:len(values)], 10, 23)})
    sheet.values_update('nvd_date!A' + str(y), params={'valueInputOption': 'RAW'}, body={'values': split(values[0:len(values)], 23, 27)}) 

def update_nipc(keys, values):

    y = len(get_values("nipc_type")) + 1

    sheet.worksheet('nipc_type').add_rows(len(values))
    sheet.worksheet('nipc_data').add_rows(len(values))

    sheet.values_update('nipc_type!A1', params={'valueInputOption': 'RAW'}, body={'values': [keys[0:10]]})
    sheet.values_update('nipc_data!A1', params={'valueInputOption': 'RAW'}, body={'values': [keys[10:len(keys)]]})


    sheet.values_update('nipc_type!A' + str(y), params={'valueInputOption': 'RAW'}, body={'values': split(values, 0, 10)})
    sheet.values_update('nipc_data!A' + str(y), params={'valueInputOption': 'RAW'}, body={'values': split(values, 10, len(values[0]))})

"""________________________________________________________________________________________________________________________________
HELPER FUNCTIONS
"""
# combines two list matrices into one, currently unused
def combine(nvd1, nvd2):
    nparr1 = np.array(nvd1)
    nparr2 = np.array(nvd2)
    nplist = np.append(nparr1, nparr2, axis=1)
    nplist = nplist.tolist()
    return nplist

# splits data sets from columns a to b
def split(list, a, b):
    nplist = np.array(list, dtype=object)
    nplist = nplist[:,a:b]
    nplist = nplist.tolist()
    return nplist



"""________________________________________________________________________________________________________________________________
MAIN FUNCTIONS

Feeds data into the google spreadsheet.
Keys are first row
Values are matrix of vulnerability info
"""
def feed_nvd(keys, values):
    sheet.values_update('nvd_type!A1', params={'valueInputOption': 'RAW'}, body={'values': [keys[0:10]]})
    sheet.values_update('nvd_data!A1', params={'valueInputOption': 'RAW'}, body={'values': [keys[14:27]]})
    sheet.values_update('nvd_date!A1', params={'valueInputOption': 'RAW'}, body={'values': [keys[10:14]]})



    #Splits up the data since Google Sheets can't take that much at once
    y = 2
    while values:
        sheet.worksheet("nvd_type").add_rows(1)
        sheet.worksheet("nvd_data").add_rows(1)
        sheet.worksheet("nvd_date").add_rows(1)
        if len(values) > 50000:
            sheet.values_update('nvd_type!A' + str(y), params={'valueInputOption': 'RAW'}, body={'values': split(values[0:50000], 0, 10)})
            sheet.values_update('nvd_data!A' + str(y), params={'valueInputOption': 'RAW'}, body={'values': split(values[0:50000], 14, 27)})
            sheet.values_update('nvd_date!A' + str(y), params={'valueInputOption': 'RAW'}, body={'values': split(values[0:50000], 10, 14)})        
            del values[:50000]
            y = y + 50000
        else:
            sheet.values_update('nvd_type!A' + str(y), params={'valueInputOption': 'RAW'}, body={'values': split(values[0:len(values)], 0, 10)})  
            sheet.values_update('nvd_data!A' + str(y), params={'valueInputOption': 'RAW'}, body={'values': split(values[0:len(values)], 14, 27)})
            sheet.values_update('nvd_date!A' + str(y), params={'valueInputOption': 'RAW'}, body={'values': split(values[0:len(values)], 10, 14)})           
            del values[:]

def feed_nipc(keys, values):
    sheet.values_update('nipc_type!A1', params={'valueInputOption': 'RAW'}, body={'values': [keys[0:10]]})
    sheet.values_update('nipc_data!A1', params={'valueInputOption': 'RAW'}, body={'values': [keys[10:len(keys)]]})

    y = 2
    sheet.values_update('nipc_type!A' + str(y), params={'valueInputOption': 'RAW'}, body={'values': split(values, 0, 10)})
    sheet.values_update('nipc_data!A' + str(y), params={'valueInputOption': 'RAW'}, body={'values': split(values, 10, len(values[0]))})

