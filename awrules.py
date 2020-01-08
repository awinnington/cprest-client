###
# Uses https://github.com/CheckPointSW/cp_mgmt_api_python_sdk
# Connecting to remote CheckPoint MGMT server
#
#
##


# A package for reading passwords without displaying them on the console.
from __future__ import print_function

import sys, os
import json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# cpapi is a library that handles the communication with the Check Point management server.
from cpapi import APIClient, APIClientArgs


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

        print("Processing. Please wait...")
        show_access_layers_res = client.api_query("show-access-layers", "standard")
        if show_access_layers_res.success is False:
            print("Failed to get the list of all host objects:\n{}".format(show_hosts_res.error_message))
            exit(1)

        layerarr = []

        ##print(show_access_layers_res.data)
        layers = show_access_layers_res.data['access-layers']

        for layer in layers:
            ##print(layer['name'])
            layerarr.append(layer['name'])

        print(layerarr)

        print("************************")

        awrulebase = {}
        awrulearr = []

        cmddata = {}
        cmddata['name'] = ""
        cmddata['use-object-dictionary'] = 'false'
        cmddata['show-hits'] = 'true'

        for layer in layerarr:
            cmddata['name'] = layer
            cmddata['offset'] = 0
            show_access_rulebase_res = client.api_call("show-access-rulebase", cmddata)
            ##            print(show_access_rulebase_res.data['to'])
            ##            print(show_access_rulebase_res.data['total'])
            awrulearr = show_access_rulebase_res.data['rulebase']
            while show_access_rulebase_res.data['total'] > show_access_rulebase_res.data['to']:
                cmddata['offset'] = show_access_rulebase_res.data['to']
                show_access_rulebase_res = client.api_call("show-access-rulebase", cmddata)
                awrulearr += show_access_rulebase_res.data['rulebase']

            awrulebase[layer] = awrulearr

        awrulebase_pretty = json.dumps(awrulebase, indent=2)
        print(awrulebase_pretty)

        with open('awpyrules.json', 'w') as outfile:
            outfile.write(awrulebase_pretty)


if __name__ == "__main__":
    main()
