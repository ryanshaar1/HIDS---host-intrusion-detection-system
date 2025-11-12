import file_monitor
import time 
import threading


folder_path = "C:/Users/Ryan/OneDrive/מסמכים/CODING/VSCODE/pythonLearning/python/HIDS - host intrusion detection system/agent/sensitive"
folder_config_path = "C:/Users/Ryan/OneDrive/מסמכים/CODING/VSCODE/pythonLearning/python/HIDS - host intrusion detection system/agent/folder_entry_count.json"
file_path = "C:/Users/Ryan/OneDrive/מסמכים/CODING/VSCODE/pythonLearning/python/HIDS - host intrusion detection system/agent/test.txt"
config_path = "C:/Users/Ryan/OneDrive/מסמכים/CODING/VSCODE/pythonLearning/python/HIDS - host intrusion detection system/agent/file_hash.json"
permissions_config_path = "C:/Users/Ryan/OneDrive/מסמכים/CODING/VSCODE/pythonLearning/python/HIDS - host intrusion detection system/agent/file_permissions.json"

def main():
    init()
    thread_file_changed = threading.Thread(target= file_monitor.compare_hashes(file_path))
    thread_file_perm_changed = threading.Thread(target= file_monitor.premissions_changed(folder_path))
    thread_folder_changed = threading.Thread(target=file_monitor.check_entry_count(folder_path))
    thread_folder_file_deleated = threading.Thread(target=file_monitor.is_file_deleted(file_path))
    
    while True:
        thread_file_changed.start()
        thread_file_perm_changed.start()
        thread_folder_changed.start()
        thread_folder_file_deleated.start()
        time.sleep(30)

def init():
    file_monitor.add_filehash_to_json(file_path)
    file_monitor.add_folder_entry_count(folder_path)
    file_monitor.add_premission_to_json(folder_path)


     
if __name__ == "__main__":
    main()