import subprocess


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


def main():
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
