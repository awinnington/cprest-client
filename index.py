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

        print("Processing. Please wait...")

        IPv4 = sys.argv[1]
        print(IPv4)

        IPv4obj = {}
        IPv4obj['remove'] = {'delete-host': [], 'set-group': [], 'set-access-rule': []}
        IPv4obj['garbage'] = []
        IPv4obj['restore'] = []

        cmddata = {'ip-only': 'true', 'details-level': 'full', 'type': 'host'}
        cmddata['filter'] = IPv4
        cmddata['offset'] = 0

        show_objects_res = client.api_call("show-objects", cmddata)
        if show_objects_res.success is False:
            print('Failed to show objects all host objects:\n{}'.format(show_objects_res.error_message))
            exit(1)

        hosts = show_objects_res.data['objects']

        for host in hosts:
            # hostarr.append(host['uid'])
            print("START OF HOST: ", host['name'])
            if host['ipv4-address'] != IPv4:
                print("IP Address of object does not match command line, exiting for caution")
                exit(1)

            cmd = "delete-host"
            data1 = {'name': host['name']}
            IPv4obj['remove'][cmd].append(data1)

            if host['groups']:
                for group in host['groups']:
                    cmd = "set-group"
                    data = {'name': group['name'], 'members': {'remove': host['name']}}
                    IPv4obj['remove'][cmd].append(data)

            cmddata = {}
            cmddata['uid'] = host['uid']
            show_where_used_res = client.api_call("where-used", cmddata)
            tempobj = show_where_used_res.data['used-directly']

            for key in tempobj.keys():
                print("the current key is:", key)
                if key.startswith('objects') & bool(tempobj[key]):
                    for cpobject in tempobj[key]:
                        objarr = []
                        groupobj = {}
                        print(cpobject['type'])
                        # if cpobject['type'] == 'group':

                        #
                        #  Got groups covered, need to find other objects
                        #  TODO: Come back here and add other objects
                        #

                elif key.startswith('access-control-rules') & bool(tempobj[key]):
                    print("Object has access rules")
                    for cpobject in tempobj[key]:
                        rcolumns = cpobject['rule-columns']
                        ruid = cpobject['rule']['uid']
                        rlayer = cpobject['layer']['name']
                        cmddata = {}
                        cmddata['uid'] = ruid
                        cmddata['layer'] = rlayer
                        for column in rcolumns:
                            cmd = "set-access-rule"
                            data = {'layer': rlayer, 'uid': ruid, column: {'remove': host['name']}}
                            IPv4obj['remove'][cmd].append(data)

                elif tempobj[key]:
                    if key == 'total':
                        print("")
                    else:
                        IPv4obj['garbage'].insert(0, tempobj[key])

            print("END of HOST", host['name'])
            print("")

        #
        #  When the hosts are done
        #

        IPv4obj_pretty = json.dumps(IPv4obj, indent=2)
        print("")
        # print(IPv4obj_pretty)

        with open('host.json', 'w') as outfile:
            outfile.write(IPv4obj_pretty)


if __name__ == "__main__":
    main()
