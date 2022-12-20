from fastapi import FastAPI
from pydantic import BaseModel
import pickle
import json


app = FastAPI()

class model_input(BaseModel):

    duration : int
    protocol_type : int
    flag : int
    src_bytes : int
    dst_bytes : int
    land : int
    wrong_fragment : int
    urgent : int
    hot : int
    num_failed_logins : int
    logged_in : int
    num_compromised : int
    root_shell : int
    su_attempted : int
    num_file_creations : int
    num_shells : int
    num_access_files : int
    is_host_login : int
    is_guest_login : int
    count : int
    srv_count : int
    serror_rate : int
    rerror_rate : int
    same_srv_rate : int
    diff_srv_rate : int
    srv_diff_host_rate : int
    dst_host_count : int
    dst_host_srv_count : int
    dst_host_diff_srv_rate : int
    dst_host_same_src_port_rate : int
    dst_host_srv_diff_host_rate : int      
        
# loading the saved model
model = pickle.load(open('model.pickle', 'rb'))

@app.post('/prediction')
def predd(input_parameters : model_input):
    
    input_data = input_parameters.json()
    input_dictionary = json.loads(input_data)

    duration = input_dictionary['duration']
    protocol_type = input_dictionary['protocol_type']
    flag = input_dictionary['flag']
    src_bytes = input_dictionary['src_bytes']
    dst_bytes = input_dictionary['dst_bytes']
    land = input_dictionary['land']
    wrong_fragment = input_dictionary['wrong_fragment']
    urgent = input_dictionary['urgent']
    hot = input_dictionary['hot']
    num_failed_logins = input_dictionary['num_failed_logins']
    logged_in = input_dictionary['logged_in']
    num_compromised = input_dictionary['num_compromised']
    root_shell = input_dictionary['root_shell']
    su_attempted = input_dictionary['su_attempted']
    num_file_creations = input_dictionary['num_file_creations']
    num_shells = input_dictionary['num_shells']
    num_access_files = input_dictionary['num_access_files']
    is_host_login = input_dictionary['is_host_login']
    is_guest_login = input_dictionary['is_guest_login']
    count = input_dictionary['count']
    srv_count = input_dictionary['srv_count']
    serror_rate = input_dictionary['serror_rate']
    rerror_rate = input_dictionary['rerror_rate']
    same_srv_rate = input_dictionary['same_srv_rate']
    diff_srv_rate = input_dictionary['diff_srv_rate']
    srv_diff_host_rate = input_dictionary['srv_diff_host_rate']
    dst_host_count = input_dictionary['dst_host_count']
    dst_host_srv_count = input_dictionary['dst_host_srv_count']
    dst_host_diff_srv_rate = input_dictionary['dst_host_diff_srv_rate']
    dst_host_same_src_port_rate = input_dictionary['dst_host_same_src_port_rate']
    dst_host_srv_diff_host_rate = input_dictionary['dst_host_srv_diff_host_rate']


    
    
    input_list = [duration, protocol_type, flag, src_bytes, dst_bytes, land, wrong_fragment, urgent, hot, num_failed_logins, logged_in, num_compromised, root_shell, su_attempted, num_file_creations, num_shells, num_access_files, is_host_login, is_guest_login, count, srv_count, serror_rate, rerror_rate, same_srv_rate, diff_srv_rate, srv_diff_host_rate, dst_host_count, dst_host_srv_count, dst_host_diff_srv_rate, dst_host_same_src_port_rate, dst_host_srv_diff_host_rate]
    
    prediction = model.predict([input_list])
    return prediction[0]