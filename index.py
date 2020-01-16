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
        IPv4obj['remove'] = []
        IPv4obj['garbage'] = []
        IPv4obj['restore'] = []

        cmddata = {'ip-only': 'true', 'details-level': 'full', 'type': 'host'}
        cmddata['filter'] = IPv4
        cmddata['offset'] = 0

        show_objects_res = client.api_call("show-objects", cmddata)
        if show_objects_res.success is False:
            print("Failed to get the list of all host objects:\n{}".format(show_access_layers_res.error_message))
            exit(1)

        hostarr = []
        hosts = show_objects_res.data['objects']

        #
        # Test to see if the IP address matches the command line
        #

        for host in hosts:
            # hostarr.append(host['uid'])
            print("START OF HOST: ", host['name'])
            if host['ipv4-address'] != IPv4:
                print("IP Address of object does not match command line, exiting for caution")
                exit(1)

            cmd = "delete-host"
            data = {'name': host['name']}
            tmplist = [cmd, data]
            IPv4obj['remove'].append(tmplist)
            cmd = "add-host"
            data = host
            tmplist = [cmd, data]
            IPv4obj['restore'].append(tmplist)

            # Pull the groups out of the show objects

            # print(host['groups'])
            if len(host['groups']) > 0:
                for group in host['groups']:
                    if len(group['members']) > 1:
                        cmd = "set-group"
                        data = {'name': group['name'], 'members': {'remove': host['name']}}
                        tmplist = [cmd, data]
                        IPv4obj['remove'].append(tmplist)
                        data = {'name': group['name'], 'members': {'add': host['name']}}
                        tmplist = [cmd, data]
                        IPv4obj['restore'].append(tmplist)
                    else:
                        cmd = "set-group"
                        data = {'name': group['name'], 'members': {'remove': host['name']}}
                        tmplist = [cmd, data]
                        IPv4obj['garbage'].append(tmplist)

            cmddata = {}
            cmddata['uid'] = host['uid']
            show_where_used_res = client.api_call("where-used", cmddata)
            # print(show_where_used_res.data)

            tempobj = show_where_used_res.data['used-directly']

            # print(tempobj.keys())
            if tempobj['objects']:
                for cpobject in tempobj['objects']:
                    objarr = []
                    groupobj = {}
                    print(cpobject['type'])
                    # if cpobject['type'] == 'group':

                    #
                    #  Got groups covered, need to find other objects
                    #  TODO: Come back here and add other objects
                    #

            if tempobj['threat-prevention-rules']:
                IPv4obj['garbage'].append(tempobj['threat-prevention-rules'])

            if tempobj['nat-rules']:
                IPv4obj['garbage'].append(tempobj['nat-rules'])

            # if len(tempobj['access-control-rules']) > 0:

            if tempobj['access-control-rules']:
                print("Object has access rules")
                for cpobject in tempobj['access-control-rules']:
                    # print(cpobject)
                    # print("CPOBJECT Keys:", cpobject.keys())
                    rcolumns = cpobject['rule-columns']
                    ruid = cpobject['rule']['uid']
                    rlayer = cpobject['layer']['name']

                    cmddata = {}
                    cmddata['uid'] = ruid
                    cmddata['layer'] = rlayer
                    show_access_rule_res = client.api_call("show-access-rule", cmddata)
                    for column in rcolumns:
                        # print("The length of ", column, " is ", len(show_access_rule_res.data[column]))
                        # print(show_access_rule_res.data[column])
                        uniqip = set()
                        for tmpx in show_access_rule_res.data[column]:
                            uniqip.add(tmpx['ipv4-address'])
                        # print(len(uniqip))
                        if len(uniqip) > 1:
                            cmd = "set-access-rule"
                            data = {'layer': rlayer, 'uid': ruid, column: {'remove': host['name']}}
                            tmplist = [cmd, data]
                            IPv4obj['remove'].append(tmplist)
                            data = {'layer': rlayer, 'uid': ruid, column: {'add': host['name']}}
                            tmplist = [cmd, data]
                            IPv4obj['restore'].append(tmplist)
                        else:
                            cmd = "set-access-rule"
                            data = {'layer': rlayer, 'uid': ruid, column: {'remove': host['name']}}
                            tmplist = [cmd, data]
                            IPv4obj['garbage'].append(tmplist)

            print("END of HOST", host['name'])
            print("")
        #
        #  When the hosts are done
        #

        IPv4obj_pretty = json.dumps(IPv4obj, indent=2)
        print("")
        print(IPv4obj_pretty)

        # print(tempobj['access-control-rules'])
        #
        # Can't be:
        #  Last as source
        #  Last in destination
        #  Same IP even if different objects for all the sources, or dests
        #  Any rule other then access-rule
        #  Last Member of a group
        #
        #


if __name__ == "__main__":
    main()
