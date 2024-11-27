
## Wi-Fi Configuration Tool for YoctoHub-Wireless-n

This is a Python-based GUI tool to help users configure 
a **YoctoHub-Wireless-n** device to connect to an
existing Wi-Fi network. It leverages the Yoctopuce 
programming library to interact with the YoctoHub 
over USB.

### Starting the tool

If you want to run this tool from its Python source code,
ensure that you have Python 3.x installed on your machine.
Copy the whole project directory tree to a place of your
choice (including the `cdll` subdirectory) and run the 
following command:

```bash
python configurator.py
```

### Creating a stand-alone executable

If you want to distribute this tool (or a derived work) 
to your customers, you can create a stand-alone executable 
using **PyInstaller** using the following commands

```bash
pip install -U pyinstaller
pyinstaller --onefile --add-data cdll:cdll configurator.py
```

The resulting executable will end up in a `dist` subdirectory. 
Note that you will need to run this command on each platform 
that you want to support to create a platform-specific executable. 
