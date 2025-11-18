import psutil
from file_monitor import count_entries_in_folder_os
import wmi
import pythoncom
import os
import time

critical_process_paths = [
    r"C:/Windows/System32/smss.exe",
    r"C:/Windows/System32/csrss.exe",
    r"C:/Windows/System32/wininit.exe",
    r"C:/Windows/System32/services.exe",
    r"C:/Windows/System32/lsass.exe",
    r"C:/Windows/System32/winlogon.exe",
    r"C:/Windows/explorer.exe",
    r"C:/Windows/System32/svchost.exe",
    r"C:/Windows/System32/taskhostw.exe",
    r"C:/Windows/System32/RuntimeBroker.exe",
]

critical_process_names = [
    r"smss.exe",
    r"csrss.exe",
    r"wininit.exe",
    r"services.exe",
    r"lsass.exe",
    r"winlogon.exe",
    r"explorer.exe",
    r"svchost.exe",
    r"taskhostw.exe",
    r"RuntimeBroker.exe",
]

suspicious_process_locations = [
    "C:/Users/Ryan/OneDrive/מסמכים/CODING/VSCODE/pythonLearning/python/HIDS - host intrusion detection system/agent/sensitive",
    "C:/Users/Public/",
    "C:/Users/Default/",
    "C:/Users/Default User/",
    "C:/Users/All Users/",
    "C:/Users/%USERNAME%/AppData/Local/Temp/",
    "C:/Users/%USERNAME%/AppData/Roaming/",
    "C:/Windows/Temp/",
    "C:/Windows/Tasks/",
    "C:/Windows/Prefetch/",
    "C:/Windows/Fonts/",
    "C:/Windows/System32/Tasks/",
    "C:/Temp/",
    "C:/PerfLogs/",
    "C:/ProgramData/",
    "C:/Recycle.Bin/",
    "C:/ $Recycle.Bin/",
    "C:/Program Files/Common Files/System/",
    "C:/Program Files (x86)/Common Files/System/",
]

processes = []
process_pids = []
dictionary = {}

def create_processes_lists():
    """
    Creates baseline lists of running processes and their PIDs.
    This is used to detect new processes later.
    """
    f = wmi.WMI()
    for process in f.Win32_Process():
        processes.append(process.Name)
        process_pids.append(process.ProcessId)

def check_new_processes():
    """
    Detects new or suspicious processes running from abnormal or dangerous locations.
    Uses WMI inside a thread-safe environment with CoInitialize().
    Returns HIGH severity alerts if a suspicious process is found.
    """
    pythoncom.CoInitialize()
    try:
        f = wmi.WMI()
        for process in f.Win32_Process():
            if process.ExecutablePath:
                folder_path = os.path.dirname(process.ExecutablePath)
            if process.Name not in processes and folder_path in suspicious_process_locations:
                return "HEIGH",f"suspicious process running: {process.Name} in {folder_path}"
            elif process in processes and folder_path in suspicious_process_locations and process.ProcessId not in process_pids:
                return "HEIGH",f"suspicious process running: {process.Name} in {folder_path}"
            else:
                return None,None
    except:
        return None,None
    finally:
        pythoncom.CoUninitialize()

def create_dictionary_of_length_of_processes():
    """
    Creates a dictionary mapping suspicious directories to the number of files inside them.
    Useful for detecting unauthorized file drops or persistence mechanisms.
    """
    for entry in suspicious_process_locations:
        length = count_entries_in_folder_os(entry)
        dictionary.update({entry: length})

def is_process_running_by_name(process_name):
    """Checks if a given process name is currently running using psutil."""
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] == process_name:
            return True
    return False

def all_processes_running():
    """
    Verifies that all critical system processes are running.
    Alerts with CRITICAL severity if a required system process is missing.
    """
    for process in critical_process_names:
        if not is_process_running_by_name(process):
            return "CRITICAL",f"process {process} is not running"
    return None,None

def main():
    """
    Main entry point for initializing baseline data
    and triggering process monitoring.
    """
    create_processes_lists()
    print("setup over")
    time.sleep(30)
    check_new_processes()

if __name__ == "__main__":
    main()
