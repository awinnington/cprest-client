###
# Uses https://github.com/CheckPointSW/cp_mgmt_api_python_sdk
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

        login_res = client.login(username, password)

        if login_res.success is False:
            print("Login failed:\n{}".format(login_res.error_message))
            exit(1)

        ### Actual Code Starts here ###

        res = client.api_call("show-sessions", {"details-level": "full"})
        openchanges = False
        for session in res.data['objects']:
            if session['changes'] > 0:
                print(session['user-name'], " has ", session['changes'], " changes open and is UID: ", session['uid'])
                openchanges = True

        if openchanges == False:
            print("No sessions with changes pending")

        # res_pretty = json.dumps(res.data, indent=2)
        # print(res_pretty)

        #        client.api_call("switch-session", {"uid": "07283b1f-5a50-41db-be55-71cbdfaae1be"})

        #        res = client.api_call("publish", {})
        #        if res.success is False:
        #            discard_write_to_log_file(api_client,
        #                                      "Publish failed. Error:\n{}\nAborting all changes.".format(res.error_message))
        #            return False

        client.api_call("logout", {})


if __name__ == "__main__":
    main()
