from flask_cors import CORS
from flask import Flask, jsonify
import file_monitor
import process_monitor
import network_monitor
import time 
import threading

app = None
alerts = []
all_alerts = []

def init_flask():
    global app
    app = Flask(__name__)
    CORS(app, resources={r"/*": {"origins": "*"}})

init_flask()

def create_alert(level, content):
    global alerts
    alert = {}
    alert["type"] = level
    alert["content"] = content
    if alert["content"] not in all_alerts:
        alerts.append(alert)
        all_alerts.append(alert["content"])

@app.route("/getAlerts", methods=["GET", "OPTIONS"])
def get_alerts():
    global alerts
    to_send = list(alerts)
    alerts = []
    return jsonify(to_send)

def compare_hashes_alert( ):
    severity,content = file_monitor.compare_hashes(file_path)
    create_alert(severity, content)

def permission_changed_alert():
    severity,content = file_monitor.premissions_changed(folder_path)
    create_alert(severity, content)

def check_entry_count_alert():
    severity,content = file_monitor.check_entry_count(folder_path)
    create_alert(severity, content)

def is_file_deleted_alert():
    severity,content = file_monitor.is_file_deleted(file_path)
    create_alert(severity, content)

def check_new_processes_alert():
    severity,content = process_monitor.check_new_processes()
    create_alert(severity, content)

def all_processes_running_alert():
    severity,content = process_monitor.all_processes_running()
    create_alert(severity, content)

def checking_if_new_sus_open_ports_opened_alert():
    severity,content = network_monitor.checking_if_new_sus_open_ports_opened()
    create_alert(severity, content)

def honeypot_event_loop_alert():
    severity,content = network_monitor.honeypot_event_loop()
    create_alert(severity, content)

def rate_monitoring_alert():
    severity,content = network_monitor.rate_monitoring()
    create_alert(severity, content)

folder_path = "C:/Users/Ryan/OneDrive/מסמכים/CODING/VSCODE/pythonLearning/python/HIDS - host intrusion detection system/agent/sensitive"
folder_config_path = "C:/Users/Ryan/OneDrive/מסמכים/CODING/VSCODE/pythonLearning/python/HIDS - host intrusion detection system/agent/folder_entry_count.json"
config_path = "C:/Users/Ryan/OneDrive/מסמכים/CODING/VSCODE/pythonLearning/python/HIDS - host intrusion detection system/agent/file_hash.json"
permissions_config_path = "C:/Users/Ryan/OneDrive/מסמכים/CODING/VSCODE/pythonLearning/python/HIDS - host intrusion detection system/agent/file_permissions.json"
file_path = "C:/Users/Ryan/OneDrive/מסמכים/CODING/VSCODE/pythonLearning/python/HIDS - host intrusion detection system/agent/test.txt" 

def main():
    while True:
        t1 = threading.Thread(target=compare_hashes_alert)
        t2 = threading.Thread(target=permission_changed_alert)
        t3 = threading.Thread(target=check_entry_count_alert)
        t4 = threading.Thread(target=is_file_deleted_alert)
        t5 = threading.Thread(target=check_new_processes_alert)
        t6 = threading.Thread(target=all_processes_running_alert)
        t7 = threading.Thread(target=checking_if_new_sus_open_ports_opened_alert)
        t8 = threading.Thread(target=rate_monitoring_alert)


        t1.start(); t2.start(); t3.start(); t4.start(); t5.start(); t6.start(); t7.start(); t8.start()
        t1.join(); t2.join(); t3.join(); t4.join(); t5.join(); t6.join(); t7.join(); t8.join()

        time.sleep(30)

def init():
    file_monitor.add_filehash_to_json(file_path)
    file_monitor.add_folder_entry_count(folder_path)
    file_monitor.add_premission_to_json(folder_path)

    process_monitor.create_processes_lists()
    process_monitor.create_dictionary_of_length_of_processes()

    network_monitor.getting_my_open_ports_list()
    network_monitor.detect_scanners_setup()
    



if __name__ == "__main__":
    init()
    
    flask_thread = threading.Thread(target=app.run, kwargs={"host":"0.0.0.0", "port":5000})
    honeypot_thread = threading.Thread(target=honeypot_event_loop_alert)

    flask_thread.start()
    main()
