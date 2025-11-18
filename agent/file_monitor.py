import hashlib
import os
import json
import stat


folder_path = "C:/Users/Ryan/OneDrive/מסמכים/CODING/VSCODE/pythonLearning/python/HIDS - host intrusion detection system/agent/sensitive"
folder_config_path = "C:/Users/Ryan/OneDrive/מסמכים/CODING/VSCODE/pythonLearning/python/HIDS - host intrusion detection system/agent/folder_entry_count.json"
config_path = "C:/Users/Ryan/OneDrive/מסמכים/CODING/VSCODE/pythonLearning/python/HIDS - host intrusion detection system/agent/file_hash.json"
permissions_config_path = "C:/Users/Ryan/OneDrive/מסמכים/CODING/VSCODE/pythonLearning/python/HIDS - host intrusion detection system/agent/file_permissions.json"
file_path = "C:/Users/Ryan/OneDrive/מסמכים/CODING/VSCODE/pythonLearning/python/HIDS - host intrusion detection system/agent/test.txt" 


def add_filehash_to_json(file):
    """
    Calculates the SHA-256 hash of a given file and stores it in the hash config JSON.
    Updates the existing JSON with {file_path: file_hash}.
    """
    try:
        with open(file, 'r', encoding="utf-8") as f:
            content = f.read()
            sha256 = hashlib.sha256()
            sha256.update(content.encode())
            file_hash = sha256.hexdigest()

            file_dict = {file: file_hash}
            update_json(config_path, file_dict)

    except Exception as e:
        print(e)


def compare_hashes(file):
    """
    Compares the current SHA-256 hash of a file to the stored hash in the JSON.
    Returns a CRITICAL alert if the hash changed, otherwise (None, None).
    """
    try:
        with open(file, 'r', encoding="utf-8") as f:
            content = f.read()
            sha256 = hashlib.sha256()
            sha256.update(content.encode())
            file_hash = sha256.hexdigest()

        with open(config_path, 'r') as c:
            c_json = json.load(c)
            if c_json[file] != file_hash:
                return "CRITICAL", f"file changed: {file}"

        return None, None

    except Exception as e:
        print(e)
        return None, None


def does_hash_exist(file):
    """
    Checks if a file path exists as a key in the hash JSON.
    Returns True if exists, False otherwise.
    """
    with open(config_path, 'r') as c:
        c_json = json.load(c)
        return file in c_json.keys()


def is_file_deleted(file):
    """
    Checks if the file was deleted since last recorded.
    Returns CRITICAL alert if deleted, otherwise (None, None).
    """
    if not os.path.exists(file):
        return "CRITICAL", f"the file was deleted: {file}"
    return None, None


def count_entries_in_folder_os(folder_path):
    """
    Counts the number of files and folders in a given folder using os.listdir().
    Handles permission errors safely.
    """
    if not os.path.isdir(folder_path):
        return "Error: Folder path does not exist or is not a directory."

    file_count = 0
    try:
        for entry in os.listdir(folder_path):
            file_count += 1
    except PermissionError:
        print(f"Permission denied: {folder_path}")
        return 0
    except Exception as e:
        print(f"Error reading folder {folder_path}: {e}")
        return 0

    return file_count


def add_folder_entry_count(folder_path):
    """
    Records the initial number of files/folders in a directory into the JSON config.
    Writes {folder_path: count}.
    """
    count = count_entries_in_folder_os(folder_path)
    dic = {folder_path: count}
    update_json(folder_config_path, dic)


def check_entry_count(folder_path):
    """
    Checks if the number of entries in a folder has changed since last recorded.
    Returns HIGH alert if changed, otherwise (None, None).
    """
    count = count_entries_in_folder_os(folder_path)
    with open(folder_config_path, 'r') as c:
        c_json = json.load(c)
        if c_json[folder_path] != count:
            return "HEIGH", f"file added or deleted from folder: was {c_json[folder_path]} now {count}"

    return None, None


def update_json(json_path, dic):
    """
    Opens a JSON file, updates it with the provided dictionary, and writes it back to disk.
    Used to store hash, permission, and folder-change data.
    """
    with open(json_path, 'r') as c:
        c_json = json.load(c)

    c_json.update(dic)

    with open(json_path, 'w') as j:
        json.dump(c_json, j)


def get_all_files_in_folder(folder_path):
    """
    Recursively walks through a folder and returns a list of all readable file paths.
    Skips files without read permission.
    """
    all_files = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            full_path = os.path.join(root, file)
            if os.access(full_path, os.R_OK):
                all_files.append(full_path)
    return all_files


def add_premission_to_json(folder_path):
    """
    Stores initial file permissions (UNIX-style bits) for all readable files in JSON.
    Saves using: {file_path: permissions}.
    """
    all_files = get_all_files_in_folder(folder_path)

    for file in all_files:
        initial_stat = os.stat(file)
        initial_perm = stat.S_IMODE(initial_stat.st_mode)
        dic = {file: initial_perm}
        update_json(permissions_config_path, dic)


def premissions_changed(file_path):
    """
    Checks if any file inside the folder has had its permission bits changed.
    Returns HIGH alert if a change is detected, otherwise (None, None).
    """
    all_files = get_all_files_in_folder(folder_path)

    with open(permissions_config_path, 'r') as c:
        c_json = json.load(c)

    for file in all_files:
        file_stat = os.stat(file)
        perm = stat.S_IMODE(file_stat.st_mode)

        if c_json[file] != perm:
            file_name = os.path.basename(file)
            return "HEIGH", f"the permissions of {file_name} in {file} changed from {c_json[file]} to {perm}"

    return None, None


def main():
    print("hi")


if __name__ == "__main__":
    main()
