#!/usr/bin/python3
""" Check response
"""
import requests
import base64
from time import sleep

if __name__ == "__main__":
    user_email = "u13@hbtn.io"
    user_pwd = "pwd13"

    r = requests.post('http://0.0.0.0:5000/api/v1/auth_session/login', data={ 'email': user_email, 'password': user_pwd })
    if r.status_code != 200:
        print("Wrong status code: {}".format(r.status_code))
        exit(1)
    if r.headers.get('content-type') != "application/json":
        print("Wrong content type: {}".format(r.headers.get('content-type')))
        exit(1)
    
    try:
        r_json = r.json()
        
        r_user_email = r_json.get('email')
        if r_user_email is None:
            print("User is not return")
            exit(1)

        if r_user_email != user_email:
            print("User returned is not the same: {}".format(r_json))
            exit(1)
        user_id = r_json.get('id')

        cookie_session_id = r.cookies.get('_my_session_id')
        if cookie_session_id is None:
            print("No cookie _my_session_id returned")
            exit(1)

        sleep(1)
            
        """ Request Me """
        r_user_me = requests.get('http://0.0.0.0:5000/api/v1/users/me', cookies={ '_my_session_id': cookie_session_id })
        if r_user_me.status_code != 200:
            print("Wrong status code: {}".format(r_user_me.status_code))
            exit(1)
        if r_user_me.headers.get('content-type') != "application/json":
            print("Wrong content type: {}".format(r_user_me.headers.get('content-type')))
            exit(1)
        
        r_user_me_json = r_user_me.json()
        
        r_user_me_id = r_user_me_json.get('id')
        if r_user_me_id is None:
            print("User is not return")
            exit(1)
        
        if r_user_me_id != user_id:
            print("User returned is not the same: {}".format(r_user_me_json))
            exit(1)

        sleep(1)

        """ Destroy Session """
        r_destroy_session = requests.delete('http://0.0.0.0:5000/api/v1/auth_session/logout', cookies={ '_my_session_id': cookie_session_id })
        if r_destroy_session.status_code != 200:
            print("Wrong status code: {}".format(r_destroy_session.status_code))
            exit(1)
        if r_destroy_session.headers.get('content-type') != "application/json":
            print("Wrong content type: {}".format(r_destroy_session.headers.get('content-type')))
            exit(1)
        
        r_destroy_session_json = r_destroy_session.json()
        if r_destroy_session_json != {}:
            print("Wrong value return: {}".format(r_destroy_session_json))
            exit(1)


        """ Request Me = fail """
        r_user_me = requests.get('http://0.0.0.0:5000/api/v1/users/me', cookies={ '_my_session_id': cookie_session_id })
        if r_user_me.status_code != 403:
            print("Wrong status code: {}".format(r_user_me.status_code))
            exit(1)
        if r_user_me.headers.get('content-type') != "application/json":
            print("Wrong content type: {}".format(r_user_me.headers.get('content-type')))
            exit(1)
        
        r_user_me_json = r_user_me.json()
        
        if len(r_user_me_json.keys()) != 1:
            print("Not the right number of element in the JSON: {}".format(r_user_me_json))
            exit(1)
        
        error_value = r_user_me_json.get('error')
        if error_value is None:
            print("Missing 'error' key in the JSON: {}".format(r_user_me_json))
            exit(1)
        if error_value != "Forbidden":
            print("'error' doesn't have the right value: {}".format(error_value))
            exit(1)

        print("OK", end="")
    except:
        print("Error, not a JSON")
