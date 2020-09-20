import os
import sys
import json
import socket
import sqlite3
import requests
import time

DB_FILE = "/home/uzr/network_scanner/net_devs.db"
conn = None #connection variable

def get_ip_mask():
    ip_address = ([l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2]
                                if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)),
                                                                    s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0])
    ip_mask = ip_address.split('.')
    ip_mask[3] = '0/24'
    ip_mask = '.'.join(ip_mask)
    return ip_mask

def get_network_devices(ip_mask):
    sys.stdout.flush()
    stream = os.popen('nmap --privileged -T polite -sn %s' %(ip_mask))
    output = stream.read()
    outputList = output.splitlines()
    init = 3
    fin = len(outputList) - 2

    devices_list = []

    for i in range(init, fin, 3):
        line0 = outputList[i]
        line1 = outputList[i+1]
        line2 = outputList[i+2] #never used, we do not need this line
        #if i % 3 == 0:
        mac = line0 [13 : 30]
        vendor = line0 [32: len(line0)-1]
        #elif i%3 ==1:
        ip = line1.replace('Nmap scan report for ', '')
        device_name = ''
        if(ip.find('(') > -1):
            device_name = ip[0: ip.find('(')-1]
            ip = ip.replace(ip[0: ip.find('(')+1], '')
            ip = ip.replace( ')', '')
        #else do nothing

        device = {
            'mac': mac,
            'ip': ip,
            'vendor': vendor,
            'device_name': device_name
        }
        devices_list.append(device)
        
    return devices_list

def db_clear_devices():
    global conn
    cur = conn.cursor()
    cur.execute("DELETE FROM devices")
    conn.commit()

def db_store_devices(devices_list):
    global conn
    cur = conn.cursor()

    for device in devices_list:
        cur.execute("INSERT INTO devices (mac, ip, vendor, device_name) VALUES ('%s', '%s', '%s', '%s')" %(device['mac'], device['ip'], device['vendor'], device['device_name']))
    conn.commit()

def create_connection(db_file):
    """ create a database connection to the SQLite database
        specified by the db_file
    :param db_file: database file
    :return: Connection object or None
    """
    global conn
    try:
        conn = sqlite3.connect(db_file)
    except Exception as e:
        print(e)
        sys.exit(1)

def select_all_devices():
    """
    Query all rows in the devices table
    :return:
    """
    global conn
    conn.row_factory = dict_factory
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices")
    devices_list = cur.fetchall()
    return devices_list

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

def get_devices_from_db():
    create_connection(DB_FILE)
    devices_list = select_all_devices()
    return devices_list

def get_connected_devices(devices_list, db_devices_list):
    disconnected_devs = []
    for d1 in devices_list:
        dev_present = False
        for d2 in db_devices_list:
            if d1['mac'] == d2['mac']:
                dev_present = True
        if not dev_present:
            disconnected_devs.append(d1)
    return disconnected_devs

def get_disconnected_devices(devices_list, db_devices_list):
    connected_devs = []
    for d1 in db_devices_list:
        dev_present = False
        for d2 in devices_list:
            if d1['mac'] == d2['mac']:
                dev_present = True
        if not dev_present:
            connected_devs.append(d1)
    return connected_devs

def scan_vendors(devices_list):
    for device in devices_list:
        mac = device['mac'].replace(":", "-")
        response = requests.get("https://api.macvendors.com/%s" %mac)
        if(response.status_code == 200):
            device['vendor'] = response.text
            time.sleep(0.5)
    return devices_list

def main():
    global conn
    ip_mask = get_ip_mask()
    devices_list = get_network_devices(ip_mask)
    devices_list = scan_vendors(devices_list)
    db_devices_list = get_devices_from_db()
    db_clear_devices()
    db_store_devices(devices_list)
    disconnected_devs = get_disconnected_devices(devices_list, db_devices_list)
    connected_devs = get_connected_devices(devices_list, db_devices_list)
    res = {
        "current_devices": devices_list,
        "connected": connected_devs,
        "disconnected": disconnected_devs
    }
    res = json.dumps(res)
    conn.close()
    print(res)
    sys.exit(0)


    
if __name__ == "__main__":
    main()