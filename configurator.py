import re
import tkinter as tk
from tkinter import ttk, messagebox
from yocto_api import YAPI, YRefParam
from yocto_network import YNetwork
from yocto_wireless import YWireless, YWlanRecord

# User interface defaults
FONT_NAME = "Arial"
FONT_SIZE = 11

# Unicode constants for eye icons
EYE_OPEN = "\U0001F441"
EYE_CLOSED = "\U0001F648"

# Yoctopuce objects
wireless: YWireless
network: YNetwork
wlans: list[YWlanRecord] = []
nameChanged = False

def detect_yoctohub():
    global wireless, network
    errmsg = YRefParam()
    errcode = YAPI.RegisterHub("usb", errmsg)
    if errcode == YAPI.DOUBLE_ACCES:
        errcode = YAPI.RegisterHub("127.0.0.1", errmsg)
        if errcode != YAPI.SUCCESS:
            errcode = YAPI.RegisterHub("usb", errmsg)
    if errcode != YAPI.SUCCESS:
        error_label.config(text="Error: "+errmsg.value)
        window.after(500, detect_yoctohub)
        return
    YAPI.UpdateDeviceList(errmsg)
    wireless = YWireless.FirstWireless()
    if wireless is None:
        error_label.config(text="No YoctoHub-Wireless-n found")
        window.after(100, detect_yoctohub)
        return
    serial = wireless.get_serialNumber()
    network = YNetwork.FindNetwork(f"{serial}.network")
    error_label.config(text="")
    init_frame.pack_forget()
    main_frame.pack(fill=tk.BOTH, expand=True)
    device_name.set(network.get_logicalName())
    device_name.trace_add("write", on_device_name_change)
    refresh_networks(True, 2)
    update_diagnostics()

def refresh_networks(quick=False, retries = 3):
    """Updates the list of available wireless networks"""
    global wlans, selected_network
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
        eye_button.config(text=EYE_CLOSED)
    else:
        password_entry.config(show="*")
        eye_button.config(text=EYE_OPEN)


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
        messagebox.showwarning("Error", "YoctoHub-Wireless-n disconnected")
        window.destroy()
        return
    ip = network.get_ipAddress()
    rdy = network.get_readiness()
    chan = wireless.get_channel()
    linkq = wireless.get_linkQuality()
    readinames = [ "down", "network exists", "network linked", "LAN ready", "WWW ready" ]
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
    window.after(500, update_diagnostics)


def on_device_name_change(*args):
    """Callback triggered when the device name changes"""
    global nameChanged
    nameChanged = True
    apply_button.config(state="normal")

def apply_device_name():
    """Applies the new device name."""
    global nameChanged
    new_name = device_name_entry.get()
    if not re.match("^[A-Za-z0-9_-]{1,15}$", new_name):
        messagebox.showerror("Invalid Name",
                             "Device name can only contain alphanumeric characters, '-', or '_'"+
                             ", and must be at most 15 characters long.")
        return False
    network.set_logicalName(new_name)
    apply_button.config(state="disabled")
    nameChanged = False
    return True

def save_settings():
    global nameChanged
    if nameChanged and not apply_device_name():
        return
    network.get_module().saveToFlash()
    window.destroy()

# Create the user interface
window = tk.Tk()
window.title("Wi-Fi configuration tool")
window.option_add("*Font", f"{FONT_NAME} {FONT_SIZE}")

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
device_name = tk.StringVar(value="MyDevice")  # Default device name
device_name_entry = tk.Entry(device_name_frame, textvariable=device_name, width=15)
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
networks_frame = tk.Frame(network_list_frame)
networks_frame.pack(fill="both", padx=5, pady=5)
selected_network = tk.StringVar(value="")

# Password entry
password_frame = tk.Frame(config_frame)
password_frame.pack(fill="x", pady=5)
password_label = tk.Label(password_frame, text="Password:", fg="gray")
password_label.pack(side="left", padx=5)
password_entry = tk.Entry(password_frame, show="*", width=30, state="disabled")
password_entry.pack(side="left", padx=5)
eye_button = tk.Button(password_frame, text=EYE_OPEN, command=toggle_password_visibility,
                       font=(FONT_NAME, FONT_SIZE+2), relief="flat", state="disabled")
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

detect_yoctohub()
main_frame.mainloop()
