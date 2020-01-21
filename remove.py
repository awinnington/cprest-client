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

        # print(myfile['remove'])
        removearr = myfile['remove']

        print("Entering Set-Group")
        cmd = 'set-group'
        if removearr[cmd]:
            for group in removearr[cmd]:

                cmddata = {}
                cmddata['name'] = group['name']
                cmddata['details-level'] = "uid"
                show_group_res = client.api_call("show-group", cmddata)
                show_group = show_group_res.data
                if len(show_group['members']) > 1:
                    cmddata['members'] = group['members']
                    cmddata['details-level'] = "standard"
                    print("set-group ", cmddata)

                    set_group_res = client.api_call(cmd, cmddata)
                    if set_group_res.success is False:
                        print("Setting Group Failed:\n{}".format(set_group_res.error_message))
                        exit(1)

                    # removecmd_res = client.api_call(cmd, cmddata)
                    # print(removecmd_res.data)

                    cmddata['members'] = {'add': group['members']['remove']}
                    print("RESTORE: set-group", cmddata)
                    tmplist = [cmd, cmddata]
                    myfile['restore'].insert(0, tmplist)

                else:
                    print("Only member, might as well clean up group")

        print("Exit Set-Group")

        print("Entering Set-Access-Rule")
        if removearr['set-access-rule']:
            for rule in removearr['set-access-rule']:
                cmddata = {}
                cmddata['layer'] = rule['layer']
                cmddata['uid'] = rule['uid']
                cmddata['details-level'] = "uid"
                show_access_rule_res = client.api_call("show-access-rule", cmddata)
                cmd = "set-access-rule"
                cmddata['details-level'] = "standard"
                if 'destination' in rule:
                    if len(show_access_rule_res.data['destination']) > 1:
                        cmddata['destination'] = rule['destination']
                        print(cmd, cmddata)

                        set_access_rule_res = client.api_call(cmd, cmddata)
                        if set_access_rule_res.success is False:
                            print("Setting Access Rule Failed:\n{}".format(set_access_rule_res.error_message))
                            exit(1)

                        cmddata['destination'] = {'add': rule['destination']['remove']}
                        print("RESTORE: ", cmd, " ", cmddata)
                        tmplist = [cmd, cmddata]
                        myfile['restore'].insert(0, tmplist)
                    else:
                        print("rule has no more destinations, disable")

                if 'source' in rule:
                    if len(show_access_rule_res.data['source']) > 1:
                        cmddata['source'] = rule['source']
                        print(cmd, cmddata)

                        set_access_rule_res = client.api_call(cmd, cmddata)
                        if set_access_rule_res.success is False:
                            print("Setting Access Rule Failed:\n{}".format(set_access_rule_res.error_message))
                            exit(1)

                        cmddata['source'] = {'add': rule['source']['remove']}
                        print("RESTORE: ", cmd, " ", cmddata)
                        tmplist = [cmd, cmddata]
                        myfile['restore'].insert(0, tmplist)

                    else:
                        print("rule has no more sources, disable")

        print("Exiting Set-Access-Rule")

        cmd = "delete-host"
        print("Entering ", cmd)
        if removearr[cmd]:
            for host in removearr[cmd]:
                cmddata = {}
                cmddata['name'] = host['name']
                print(cmd, cmddata)
                show_host_res = client.api_call('show-host', cmddata)
                if show_host_res.success is False:
                    print("Show host Failed:\n{}".format(delete_host_res.error_message))
                    exit(1)

                delete_host_res = client.api_call(cmd, cmddata)
                if delete_host_res.success is False:
                    print("Delete Host Failed:\n{}".format(delete_host_res.error_message))
                    exit(1)

                host = show_host_res.data

                cmd = "add-host"
                data = {}
                data['name'] = host['name']
                data['ipv4-address'] = host['ipv4-address']
                data['color'] = host['color']
                data['comments'] = host['comments']
                if 'host-servers' in host:
                    data['host-servers'] = host['host-servers']
                print("the restore data is: ", data)
                tmplist = [cmd, data]
                myfile['restore'].insert(0, tmplist)

        print(myfile['restore'])
        print("Exiting ", cmd)

        res = client.api_call("publish", {})
        if res.success is False:
            discard_write_to_log_file(api_client,
                                      "Publish failed. Error:\n{}\nAborting all changes.".format(res.error_message))
            return False

        client.api_call("logout", {})

        myfile_pretty = json.dumps(myfile, indent=2)
        with open('host.json', 'w') as outfile:
            outfile.write(myfile_pretty)


if __name__ == "__main__":
    main()
