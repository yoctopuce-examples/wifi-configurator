import base64
import platform
import re
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, PhotoImage, Y

from yocto_api import YAPI, YRefParam
from yocto_network import YNetwork
from yocto_wireless import YWireless

# User interface defaults
FONT_NAME = "Arial"
FONT_SIZE = 11

# Show/hide password icons
EYE_OPEN_BASE64 = """
iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAMAAAC6V+0/AAAAOVBMVEUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC8dlA9AAAAEnRSTlMAyBEL26JjjVGM7NS9r5N2P1Ml8aZ0AAAAW0lEQVQY072O
zQ6AIAyDO8bGkF95/4fVqIkHONNLmy9pWuyV0+KJfFH3o0hHdbfXg+KHjUzDG4ManU8QBjF6Sh1MYAmANIAz4MfwQGagyRoi
zvV5yNaX5vNbdQGSlwMg3bc61QAAAABJRU5ErkJggg==
"""
EYE_CLOSED_BASE64 = """
iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAMAAAC6V+0/AAAAdVBMVEUAAAAFBQUJCQkdHR0HBwcrKys7OztjY2NycnIEBAQT
ExMaGhovLy83NzdAQEBBQUFERERKSkpQUFBaWlpnZ2dtbW13d3cAAAACAgIICAgODg4WFhYaGhogICApKSk1NTU6OjpOTk5T
U1NWVlZfX19nZ2dra2uS+0oHAAAAJ3RSTlMA7uW66qB9LxTxzbyWhnhwamBVQScdC/r259TKxLOiiYBaTkw4KiLMzEeCAAAA
cklEQVQY082MVw6DQBBDty8ldEJC79z/iKxBCDgAEv7wjJ81Q94oZ7pnXRiLhL6ylIUYgR2fbKBqm8phPNlRUovSw2JRnSlG
uZRc5J6V2l8DPxLVP/D98JchN8ZcNAtFw2Zcusf/sYLzmFzVt/AuIo9pBbZbBA3Pk1BdAAAAAElFTkSuQmCC
"""


# Function to get current wifi settings

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
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show","profile"],
            capture_output=True, text=True, check=True
        )
        lines = result.stdout.strip().split("\n")
        for line in lines:
            if "All User Profile" in line:
                return line.split(":")[1].strip()
    except subprocess.CalledProcessError:
        return None
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

computer_ssid = get_current_ssid()

# Yoctopuce objects
wireless: YWireless
network: YNetwork

# Other globals
wlans: list = []
name_changed = False
not_found_msg = "No YoctoHub-Wireless-n found"


def detect_yoctohub():
    global wireless, network
    errmsg = YRefParam()
    errcode = YAPI.RegisterHub("usb", errmsg)
    if errcode == YAPI.DOUBLE_ACCES:
        errcode = YAPI.RegisterHub("127.0.0.1", errmsg)
        if errcode != YAPI.SUCCESS:
            errcode = YAPI.RegisterHub("usb", errmsg)
    if errcode != YAPI.SUCCESS:
        error_label.config(text="Error: " + errmsg.value)
        window.after(500, detect_yoctohub)
        return
    YAPI.UpdateDeviceList(errmsg)
    wireless = YWireless.FirstWireless()
    if wireless is None:
        error_label.config(text=not_found_msg)
        window.after(100, detect_yoctohub)
        return
    serial = wireless.get_serialNumber()
    network = YNetwork.FindNetwork(f"{serial}.network")
    error_label.config(text="")
    init_frame.pack_forget()
    main_frame.pack(fill=tk.BOTH, expand=True)
    window.after(500, read_current_config)


def read_current_config():
    if not network.isOnline():
        device_name.set("")
        module_disconnected()
        return
    try:
        device_name.set(network.get_logicalName())
        device_name.trace_add("write", on_device_name_change)
        refresh_networks(True, 2)
        update_diagnostics()
    except YAPI.YAPI_Exception:
        window.after(100, read_current_config)


def module_disconnected():
    global not_found_msg
    not_found_msg = "Error: the device has been disconnected"
    error_label.config(text=not_found_msg)
    main_frame.pack_forget()
    init_frame.pack(fill=tk.BOTH, expand=True)
    window.after(1000, detect_yoctohub)


def refresh_networks(quick=False, retries=3):
    """Updates the list of available wireless networks"""
    global wlans, selected_network
    if not wireless.isOnline():
        module_disconnected()
        return
    if not quick:
        wireless.startWlanScan()
        window.after(2000, refresh_networks, True, retries)
        return
    try:
        new_wlans = wireless.get_detectedWlans()
    except YAPI.YAPI_Exception:
        if retries > 0:
            window.after(1000, refresh_networks, True, retries - 1)
            return
        else:
            new_wlans = []
    if len(new_wlans) != len(wlans) and retries > 0:
        window.after(1000, refresh_networks, True, retries - 1)
    wlans = new_wlans
    for widget in networks_frame.winfo_children():
        widget.destroy()
    selected_network = tk.StringVar()
    headers = ["SSID", "Encryption", "Signal Strength"]
    for col, header in enumerate(headers):
        (tk.Label(networks_frame, text=header, font=(FONT_NAME, FONT_SIZE, "bold")).
         grid(row=0, column=col, padx=5, pady=2,sticky="w"))
    for row, wlan in enumerate(wlans, start=1):
        tk.Radiobutton(
            networks_frame,
            text=wlan.get_ssid(),
            variable=selected_network,
            value=wlan.get_ssid(),
            anchor="w"
        ).grid(row=row, column=0, sticky="w", padx=5, pady=2)
        tk.Label(networks_frame, text=wlan.get_security()).grid(row=row, column=1, sticky="w", padx=5, pady=2)
        tk.Label(networks_frame, text=wlan.get_linkQuality()).grid(row=row, column=2, sticky="w", padx=5, pady=2)
    ssid = wireless.get_ssid()
    if ssid:
        selected_network.set(ssid)
    selected_network.trace_add("write", on_network_selected)


def wlan_sec(ssid):
    global wlans
    for wlan in wlans:
        if wlan.get_ssid() == ssid:
            return wlan.get_security()
    return ""


def on_network_selected(*args):
    """Callback triggered when the selected network changes"""
    global selected_network
    ssid = selected_network.get()
    if ssid and wlan_sec(ssid) != "OPEN":
        password_entry.config(state="normal")
        password_label.config(fg="black")
        eye_button.config(state="normal")
        connect_button.config(state="normal")
    else:
        password_entry.config(state="disabled")
        password_label.config(fg="gray")
        eye_button.config(state="disabled")
        connect_button.config(state="disabled")


def toggle_password_visibility():
    """Toggles the visibility of the password"""
    if password_entry.cget('show') == "*":
        password_entry.config(show="")
        eye_button.config(image=eye_closed)
    else:
        password_entry.config(show="*")
        eye_button.config(image=eye_open)


def connect_to_wifi():
    """Triggers a connection to the selected network"""
    global wlans, selected_network
    ssid = selected_network.get()
    if not ssid:
        messagebox.showwarning("Error", "No network selected")
        return
    sec = wlan_sec(ssid)
    if sec == "OPEN":
        passkey = ""
    else:
        passkey = password_entry.get()
        if passkey == "":
            messagebox.showwarning("Error", "Password cannot be empty")
            return
        passkey = sec[:3] + ":" + passkey
    wireless.joinNetwork(ssid, passkey)


def update_diagnostics():
    """Simulates updating diagnostic information."""
    if not network.isOnline():
        module_disconnected()
        return
    try:
        ip = network.get_ipAddress()
        rdy = network.get_readiness()
        chan = wireless.get_channel()
        linkq = wireless.get_linkQuality()
        readinames = ["down", "network exists", "network linked", "LAN ready", "WWW ready"]
        conn_status.set(f"{rdy}- {readinames[rdy]}")
        last_message.set(wireless.get_message())
        if chan > 0:
            link_quality.set(f"{linkq}% (channel {chan})")
        elif linkq > 0:
            link_quality.set(f"{linkq}%")
        else:
            link_quality.set("")
        if ip == "0.0.0.0":
            ip_address.set('')
        else:
            ip_address.set(ip)
    except YAPI.YAPI_Exception:
        pass
    window.after(500, update_diagnostics)


def on_device_name_change(*args):
    """Callback triggered when the device name changes"""
    global name_changed
    name_changed = True
    apply_button.config(state="normal")


def apply_device_name():
    """Applies the new device name."""
    global name_changed
    new_name = device_name_entry.get()
    if not re.match("^[-A-Za-z0-9]{1,15}$", new_name):
        messagebox.showerror("Invalid Name",
                             "Device name can only contain alphanumeric characters and '-'" +
                             ", and must be at most 15 characters long.")
        return False
    network.set_logicalName(new_name)
    apply_button.config(state="disabled")
    name_changed = False
    return True


def save_settings():
    global name_changed
    if name_changed and not apply_device_name():
        return
    network.get_module().saveToFlash()
    window.destroy()


def apply_computer_settings():
    """Applies the wifi parameter of the computer to the Yocto-Wireless."""
    print("poeut")
    ssid = get_current_ssid()
    if ssid is None:
        messagebox.showerror("Error", "Message")
        return
    password = get_wifi_password(ssid)
    if password is None:
        messagebox.showerror("Title", "Message")
        return
    wireless.joinNetwork(ssid, password)


# Create the user interface
window = tk.Tk()
window.title("Wi-Fi configuration tool")
window.option_add("*Font", f"{FONT_NAME} {FONT_SIZE}")
eye_open = PhotoImage(data=base64.b64decode(EYE_OPEN_BASE64))
eye_closed = PhotoImage(data=base64.b64decode(EYE_CLOSED_BASE64))

# Placeholder frame (initial view)
init_frame = tk.Frame(window)
init_frame.pack(fill=tk.BOTH, expand=True)
intro_label = tk.Label(init_frame, padx=40, pady=30,
                       text="This tool will help you configure a\nYoctoHub-Wireless-n\nto connect to your Wi-Fi network.")
intro_label.pack(expand=True, fill=tk.BOTH)
error_label = tk.Label(init_frame, text="", fg="red", wraplength=400)
error_label.pack(pady=(10, 0))  # Add some spacing between the text and the error label
intro_label = tk.Label(init_frame, padx=40, pady=30,
                       text="Use a USB cable connected to the\n'Control Port' of the YoctoHub-Wireless-n\nto start the configuration.")
intro_label.pack(expand=True, fill=tk.BOTH)
close_button = ttk.Button(init_frame, text="Close", command=window.destroy)
close_button.pack(side=tk.BOTTOM, anchor="e", padx=10, pady=10)

# Main content frame (hidden initially)
main_frame = tk.Frame(window)
config_frame = tk.LabelFrame(main_frame, text="Configuration", padx=10, pady=10)
config_frame.pack(fill="both", expand=True, padx=10, pady=5)
diagnostics_frame = tk.LabelFrame(main_frame, text="Diagnostics", padx=10, pady=10)
diagnostics_frame.pack(fill="both", expand=True, padx=10, pady=5)
save_button = ttk.Button(main_frame, text="Save & Exit", command=save_settings)
save_button.pack(side=tk.BOTTOM, anchor="e", padx=10, pady=10)

# Device name configuration
device_name_frame = tk.Frame(config_frame)
device_name_frame.pack(fill="x", pady=5)
device_name_label = tk.Label(device_name_frame, text="Device Name:")
device_name_label.pack(side="left", padx=5)
device_name = tk.StringVar(value="")
device_name_entry = tk.Entry(device_name_frame, textvariable=device_name, width=18)
device_name_entry.pack(side="left", padx=5)
apply_button = ttk.Button(device_name_frame, text="Apply", command=apply_device_name, state="disabled")
apply_button.pack(side="right", padx=5)

# Network list frame
network_list_frame = tk.Frame(config_frame)
network_list_frame.pack(fill="both", pady=5)
networks_label_frame = tk.Frame(network_list_frame)
networks_label_frame.pack(fill="x")
networks_label = tk.Label(networks_label_frame, text="Available Networks:")
networks_label.pack(side="left", padx=5)
refresh_button = ttk.Button(networks_label_frame, text="Refresh", command=refresh_networks)
refresh_button.pack(side="right", padx=5)

auto_button = ttk.Button(networks_label_frame, text="Use computer settings", command=apply_computer_settings)
if computer_ssid is None:
    auto_button["state"] = tk.DISABLED

auto_button.pack(side="right", padx=5)



network_canvas=tk.Canvas(network_list_frame)

scrollbar_config = tk.Scrollbar(network_list_frame, orient="vertical", command=network_canvas.yview)
scrollbar_config.pack(side="right", fill=Y, pady=5)

network_canvas.configure(yscrollcommand=scrollbar_config.set)

networks_frame = tk.Frame(network_canvas)
networks_frame.bind("<Configure>", lambda e: network_canvas.configure(scrollregion=network_canvas.bbox("all")))
network_canvas.create_window((0, 0), window=networks_frame, anchor="nw")

network_canvas.pack(fill="both", padx=5, pady=5, expand=True)

#networks_frame.pack(fill="both", padx=5, pady=5)
selected_network = tk.StringVar(value="")

# Password entry
password_frame = tk.Frame(config_frame)
password_frame.pack(fill="x", pady=5)
password_label = tk.Label(password_frame, text="Password:", fg="gray")
password_label.pack(side="left", padx=5)
password_entry = tk.Entry(password_frame, show="*", width=30, state="disabled")
password_entry.pack(side="left", padx=5)
eye_button = tk.Button(password_frame, image=eye_open, command=toggle_password_visibility,
                       font=(FONT_NAME, FONT_SIZE + 2), relief="flat", state="disabled")
eye_button.pack(side="left")
connect_button = ttk.Button(password_frame, text="Connect", command=connect_to_wifi, state="disabled")
connect_button.pack(side="right", padx=5)

# Diagnostics section
tk.Label(diagnostics_frame, text="Connection Status:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
tk.Label(diagnostics_frame, text="Last message:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
tk.Label(diagnostics_frame, text="Link quality:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
tk.Label(diagnostics_frame, text="IP Address:").grid(row=3, column=0, sticky="w", padx=5, pady=2)
conn_status = tk.StringVar(value="")
last_message = tk.StringVar(value="")
link_quality = tk.StringVar(value="")
ip_address = tk.StringVar(value="")
tk.Label(diagnostics_frame, textvariable=conn_status).grid(row=0, column=1, sticky="w", padx=5, pady=2)
tk.Label(diagnostics_frame, textvariable=last_message).grid(row=1, column=1, sticky="w", padx=5, pady=2)
tk.Label(diagnostics_frame, textvariable=link_quality).grid(row=2, column=1, sticky="w", padx=5, pady=2)
tk.Label(diagnostics_frame, textvariable=ip_address).grid(row=3, column=1, sticky="w", padx=5, pady=2)


def on_mouse_wheel(event):
    network_canvas.yview_scroll(-1 * (event.delta // 120), "units")

window.bind_all("<MouseWheel>", on_mouse_wheel)

detect_yoctohub()
main_frame.mainloop()
