###
# Uses https://github.com/CheckPointSW/cp_mgmt_api_python_sdk
# Connecting to remote CheckPoint MGMT server
#
#
##
# A package for reading passwords without displaying them on the console
from __future__ import print_function
# cpapi is a library that handles the communication with the Check Point management server.
from cpapi import APIClient, APIClientArgs

import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def main():
    # Login to the Server
    # getting details from the support files
    #

    with open('./auth/mycpapi.json') as json_file:
        server = json.load(json_file)

    api_server = server['chkp']['host']

    with open('./auth/mycpauth.json') as json_file:
        auth = json.load(json_file)

    username = auth['user']
    password = auth['password']

    client_args = APIClientArgs(server=api_server)

    with APIClient(client_args) as client:

        # create debug file. The debug file will hold all the communication between the python script and
        # Check Point's management server.
        client.debug_file = "api_calls.json"

        # The API client, would look for the server's certificate SHA1 fingerprint in a file.
        # If the fingerprint is not found on the file, it will ask the user if he accepts the server's fingerprint.
        # In case the user does not accept the fingerprint, exit the program.
        if client.check_fingerprint() is False:
            print("Could not get the server's fingerprint - Check connectivity with the server.")
            exit(1)

        # login to server:
        login_res = client.login(username, password)
        # print(login_res.data.get("sid"))
        # sid = login_res.data.get("sid")
        # print(sid)

        if login_res.success is False:
            print("Login failed:\n{}".format(login_res.error_message))
            exit(1)

        ### Actual Code Starts here ###

        with open('./host.json') as json_file:
            myfile = json.load(json_file)

        print(myfile['restore'])
        restorearr = myfile['restore']

        for command in restorearr:
            print(command)
            cmd = command[0]
            cmddata = command[1]
            res = client.api_call(cmd, cmddata)
            if res.success is False:
                print("Command Failed:\n{}".format(res.error_message))
                exit(1)

            print("Exiting ", cmd)

        res = client.api_call("publish", {})
        if res.success is False:
            print("Publish failed. Error:\n{}\nAborting all changes.".format(res.error_message))
            return False

        client.api_call("logout", {})


if __name__ == "__main__":
    main()
