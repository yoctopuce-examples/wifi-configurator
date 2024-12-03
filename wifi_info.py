import platform
import subprocess


def get_current_ssid_macos():
    result = subprocess.run(
        ["networksetup", "-getairportnetwork", "en0"],
        capture_output=True, text=True, check=True
    )
    output = result.stdout.strip()
    if "Current Wi-Fi Network" in output:
        ssid = output.split(": ")[1]
        return ssid
    return None


def get_current_ssid_linux():
    result = subprocess.run(
        ["nmcli", "-t", "-f", "ACTIVE,SSID", "dev", "wifi"],
        capture_output=True, text=True, check=True
    )
    lines = result.stdout.strip().split("\n")
    for line in lines:
        if line.startswith("yes:"):
            return line.split(":")[1]
    return None


def get_current_ssid_win():
    result = subprocess.run(
        ["netsh", "wlan", "show","profile"],
        capture_output=True, text=True, check=True
    )
    lines = result.stdout.strip().split("\n")
    for line in lines:
        if "All User Profile" in line:
            return line.split(":")[1].strip()
    return None


def get_current_ssid():
    """
    return current used SSID
    """
    system = platform.system()
    if system == "Windows":
        return get_current_ssid_win()
    elif system == "Linux":
        return get_current_ssid_linux()
    else:
        return get_current_ssid_macos()


def get_wifi_password_macos(ssid):
    try:
        result = subprocess.run(
            ["security", "find-generic-password", "-D", "AirPort network password", "-a", ssid, "-w"],
            capture_output=True, text=True, check=True
        )
        password = result.stdout.strip()
        return password
    except subprocess.CalledProcessError as e:
        if e.returncode == 44:  # Mot de passe non trouvé
            print(f"Aucun mot de passe trouvé pour le réseau : {ssid}")
        else:
            print(f"Erreur lors de la récupération du mot de passe : {e}")
        return None


def get_wifi_password_linux(ssid):
    return None


def get_wifi_password_win(ssid):
    result = subprocess.run(
        ["netsh", "wlan", "show", "profile", f"name={ssid}", "key=clear"],
        capture_output=True, text=True, check=True
    )
    for line in result.stdout.splitlines():
        if "Key Content" in line:
            return line.split(":")[1].strip()
    return None


def get_wifi_password(ssid):
    """
    return passworkd for a wifi network
    """
    system = platform.system()
    if system == "Windows":
        return get_wifi_password_win(ssid)
    elif system == "Linux":
        return get_wifi_password_linux(ssid)
    else:
        return get_wifi_password_macos(ssid)


def main():
    ssid = get_current_ssid()
    if not ssid:
        print("Not connected to a WiFi network.")
        return

    print(f"SSID : {ssid}")
    password = get_wifi_password(ssid)
    if password:
        print(f"Passwd : {password}")
    else:
        print("Unable to get Wifi password.")


if __name__ == "__main__":
    main()
