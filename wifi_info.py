import subprocess
import platform
import os

def get_current_ssid():
    """
    Obtient le SSID du réseau Wi-Fi actuellement connecté.
    """
    try:
        result = subprocess.run(
            ["networksetup", "-getairportnetwork", "en0"],
            capture_output=True, text=True, check=True
        )
        output = result.stdout.strip()
        if "Current Wi-Fi Network" in output:
            ssid = output.split(": ")[1]
            return ssid
        return None
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de la récupération du SSID : {e}")
        return None


def get_wifi_password(ssid):
    """
    Obtient le mot de passe Wi-Fi pour un SSID donné.
    """
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


def get_current_ssid_linux():
    """
    Obtient le SSID du réseau Wi-Fi actuellement connecté.
    """
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "ACTIVE,SSID", "dev", "wifi"],
            capture_output=True, text=True, check=True
        )
        lines = result.stdout.strip().split("\n")
        for line in lines:
            if line.startswith("yes:"):
                return line.split(":")[1]
        return None
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de la récupération du SSID : {e}")
        return None

def get_wifi_password_linux(ssid):
    """
    Obtient le mot de passe Wi-Fi pour un SSID donné.
    """
    connection_file = f"/etc/NetworkManager/system-connections/{ssid}.nmconnection"
    try:
        if not os.path.exists(connection_file):
            print(f"Fichier de configuration introuvable pour le réseau : {ssid}")
            return None

        # Lire le fichier de configuration
        with open(connection_file, "r") as file:
            lines = file.readlines()
            for line in lines:
                if line.startswith("psk="):
                    return line.split("=")[1].strip()
        print(f"Aucun mot de passe trouvé pour le réseau : {ssid}")
        return None
    except Exception as e:
        print(f"Erreur lors de la récupération du mot de passe : {e}")
        return None



def main():
    system = platform.system()
    if system == "Windows":
        print("windows")
    elif system == "Linux":
        ssid = get_current_ssid_linux()
        if not ssid:
            print("Non connecté à un réseau Wi-Fi.")
            return

        print(f"SSID : {ssid}")
        password = get_wifi_password_linux(ssid)
        if password:
            print(f"Mot de passe : {password}")
        else:
            print("Impossible de récupérer le mot de passe.")
    else:
        ssid = get_current_ssid()
        if not ssid:
            print("Non connecté à un réseau Wi-Fi.")
            return

        print(f"SSID : {ssid}")
        password = get_wifi_password(ssid)
        if password:
            print(f"Mot de passe : {password}")
        else:
            print("Impossible de récupérer le mot de passe.")


if __name__ == "__main__":
    main()
