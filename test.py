import json
import requests
import numpy as np


url = 'http://127.0.0.1:8000/prediction'
input_data_for_model = {
    
    "duration" : 0,
    "protocol_type" : 1,
    "flag" : 0,
    "src_bytes" : 191,
    "dst_bytes" : 270,
    "land" : 0,
    "wrong_fragment" : 0,
    "urgent" : 0,
    "hot" : 0,
    "num_failed_logins" : 0,
    "logged_in" : 1,
    "num_compromised" : 0,
    "root_shell" : 0,
    "su_attempted" : 0,
    "num_file_creations" : 0,
    "num_shells" : 0,
    "num_access_files" : 0,
    "is_host_login" : 0,
    "is_guest_login" : 0,
    "count" : 2,
    "srv_count" : 35,
    "serror_rate" : 0.0,
    "rerror_rate" : 0.0,
    "same_srv_rate" : 1.0,
    "diff_srv_rate" : 0.0,
    "srv_diff_host_rate" : 0.14,
    "dst_host_count" : 255,
    "dst_host_srv_count" : 242,
    "dst_host_diff_srv_rate" : 0.02,
    "dst_host_same_src_port_rate" : 0.0,
    "dst_host_srv_diff_host_rate" : 0.0, 
    
    }

input_json = json.dumps(input_data_for_model)

response = requests.post(url, data=input_json)
print(response.text)