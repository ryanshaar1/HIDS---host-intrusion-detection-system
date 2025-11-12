import hashlib
import os
import json
import stat


folder_path = "C:/Users/Ryan/OneDrive/מסמכים/CODING/VSCODE/pythonLearning/python/HIDS - host intrusion detection system/agent/sensitive"
folder_config_path = "C:/Users/Ryan/OneDrive/מסמכים/CODING/VSCODE/pythonLearning/python/HIDS - host intrusion detection system/agent/folder_entry_count.json"
file_path = "C:/Users/Ryan/OneDrive/מסמכים/CODING/VSCODE/pythonLearning/python/HIDS - host intrusion detection system/agent/test.txt"
config_path = "C:/Users/Ryan/OneDrive/מסמכים/CODING/VSCODE/pythonLearning/python/HIDS - host intrusion detection system/agent/file_hash.json"
permissions_config_path = "C:/Users/Ryan/OneDrive/מסמכים/CODING/VSCODE/pythonLearning/python/HIDS - host intrusion detection system/agent/file_permissions.json"


def add_filehash_to_json(file):
    
    with open (file, 'r', encoding="utf-8") as f:
        content = f.read()
        sha256 = hashlib.sha256()
        sha256.update(content.encode())
        file_hash = sha256.hexdigest()
        file_dict = {
            file:file_hash
        }

            
        update_json(config_path, file_dict)

def compare_hashes(file):
    with open (file, 'r', encoding="utf-8") as f:
        content = f.read()
        sha256 = hashlib.sha256()
        sha256.update(content.encode())
        file_hash = sha256.hexdigest()

        with open (config_path, 'r') as c:
            c_json = json.load(c)
            if c_json[file] != file_hash:
                print("file changed")
        
def does_hash_exist(file):
    with open (config_path, 'r') as c:
        c_json = json.load(c)
        keys = c_json.keys()
        return file in keys
    
def is_file_deleted(file):
    if not os.path.exists(file):
        print("the file was deleated")
    else:
        print("the file exists")


def count_entries_in_folder_os(folder_path):
    """
    Counts the number of files and folder in a given folder using the os module.
    """
    if not os.path.isdir(folder_path):
        return "Error: Folder path does not exist or is not a directory."
    file_count = 0
    for entry in os.listdir(folder_path):
        file_count += 1
    return file_count

def add_folder_entry_count(folder_path):
    count = count_entries_in_folder_os(folder_path)
    dic = { folder_path:count }
    update_json(folder_config_path, dic)

def check_entry_count(folder_path):
    count = count_entries_in_folder_os(folder_path)
    with open (config_path, 'r') as c:
        c_json = json.load(c)
        if c_json[folder_path] != count:
            print("file added or deleted from folder")

def update_json(json_path, dic):
    with open (json_path, 'r') as c:
        c_json = json.load(c)
        c_json.update(dic)
        with open(json_path, 'w') as j:
            json.dump(c_json, j)


def file_added_in_sensitive_folder(folder_path):
    count = count_entries_in_folder_os(folder_path)
    with open (folder_config_path, 'r') as c:
        c_json = json.load(c)
        if c_json[folder_path] != count:
            print("the amount of entries in folder changed")

def get_all_files_in_folder(folder_path):
    all_files = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            full_path = os.path.join(root, file)
            all_files.append(full_path)
    return all_files

def add_premission_to_json(folder_path):
    all_files = get_all_files_in_folder(folder_path)
    
    for file in all_files:
        initial_stat = os.stat(file)
        initial_perm = stat.S_IMODE(initial_stat.st_mode)
        dic = {file:initial_perm}
        update_json(permissions_config_path, dic)
            
    
def premissions_changed(file_path):
    all_files = get_all_files_in_folder(folder_path)
    with open (permissions_config_path, 'r') as c:
        c_json = json.load(c)
        for file in all_files:
            file_stat = os.stat(file_path)
            perm = stat.S_IMODE(file_stat.st_mode)
            file_name = os.path.basename(file)

            if c_json[file] != perm:
                print(f"the premissions of {file_name} located in {file} has changed from {c_json[file]} to {perm}")
        

    
    

def main():
    #add_filehash_to_json(file_path) - working
    # compare_hashes(file_path) - working
    # does_hash_exist(file_path) - working
    # is_file_deleted(file_path) - working
    # add_folder_entry_count(folder_path) - working
    # file_added_in_sensitive_folder(folder_path) - working
    # add_premission_to_json(folder_path) - working
    # premissions_changed(folder_path) - working
    print("hi")


if __name__ == "__main__":
    main()

