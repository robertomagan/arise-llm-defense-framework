from flask import Flask, request, jsonify
from alert import Alert
from gemini import Gemini
from jinja2 import Environment, FileSystemLoader
from colorama import init, Fore, Style

import threading
import json
import os

import ansible_runner
import datetime

HOST = "192.168.0.3"
PORT = 13080

ANSIBLE_PRIVATE_DATA_DIR = "ansible"
ANSIBLE_PLAYBOOKS_DIR = "project"

TEMPLATES_DIR = "templates"
NETJSON_DIR = "netjson"

NETWORK_DEFINITION = {}

SURICATA_RULE_ID = "86682"
RECOGNIZED_ALERTS = {
    "204":{
        "trigger": "Wazuh",
        "type": "DoS",
        "signatures": None
    },
    "5763":{
        "trigger": "Wazuh",
        "type": "SSH",
        "signatures": None
    },
    "86682": {
        "trigger": "Suricata",
        "type": None,
        "signatures": { 
            "1000002": {
                "type": "DNS"
            },
            "1000003": {
                "type": "DNS"
            },
            "1000005": {
                "type": "C2"
            },
            "1000006": {
                "type": "Network Scan"
            }
        }
    }
}

ALERTS_BEING_PROCESSED = []

init(autoreset=True)
app = Flask(__name__)

def log(header, content):
    print(Fore.YELLOW + header)
    print(content)
    print(Fore.YELLOW + "------------------------------------\n")

def load_json(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

def load_network_definition():
    global NETWORK_DEFINITION
    
    NETWORK_DEFINITION = {
        'networkgraph': load_json(file_path=os.path.join(TEMPLATES_DIR, NETJSON_DIR, 'networkgraph.json')),
        'networkroutes': load_json(file_path=os.path.join(TEMPLATES_DIR, NETJSON_DIR, 'networkroutes.json'))
    }

    log(f"-- [INFO] Network definition loaded", json.dumps(NETWORK_DEFINITION))

def confirm():
    response = input("-- [CHOICE] Do you want to execute the previous playbook? (yes/no): ").strip().lower()
    return response in ["yes", "y"]

def generate_playbook_name(destination, template):
    datetime_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{destination}-{template}-{datetime_str}.yml"

def generate_playbook_name2(destination, alert_type):
    datetime_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{destination}-{alert_type}-{datetime_str}.yml"

def write_response(filename, response):
    file_path = os.path.join(ANSIBLE_PRIVATE_DATA_DIR, ANSIBLE_PLAYBOOKS_DIR, filename)
    with open(file_path, 'w') as f:
        f.write(response)

def register_alert(alert):
    global ALERTS_BEING_PROCESSED
    ALERTS_BEING_PROCESSED.append(alert)

def delete_alert(alert):
    global ALERTS_BEING_PROCESSED
    ALERTS_BEING_PROCESSED.remove(alert)

def check_alert_being_processed(alert):
    global ALERTS_BEING_PROCESSED
    
    if alert in ALERTS_BEING_PROCESSED:
        matching_alert = next((registered_alert for registered_alert in ALERTS_BEING_PROCESSED if registered_alert == alert), None)
        log("--[DEBUG] The alert is already being processed!", json.dumps(matching_alert))
        return True
    else:
        print("--[DEBUG] Alert first time!")
        return False

def get_alert_classification(json_data):
    rule_id = json_data.get("rule").get("id")
    rule_type = None
    signature_id = None

    if rule_id in RECOGNIZED_ALERTS:
        if rule_id == SURICATA_RULE_ID:
            signature_id = json_data.get("data").get("alert").get("signature_id")
            if signature_id in RECOGNIZED_ALERTS[rule_id]["signatures"]:
                rule_type = RECOGNIZED_ALERTS[rule_id]["signatures"][signature_id]["type"]
            else:
                return None
        else:
            rule_type = RECOGNIZED_ALERTS[rule_id]["type"]
        
        return {
            "trigger": RECOGNIZED_ALERTS[rule_id]["trigger"],
            "id": rule_id,
            "type": rule_type,
            "signature_id": signature_id,
            #"timestamp": json_data.get("timestamp"),
            "agent_ip": json_data.get("agent").get("ip")
            # "src_ip": json_data.get("data").get("alert").get("src_ip", ""),
            # "dest_ip": json_data.get("data").get("alert").get("dest_ip", "")
        }
    else:
        return None

def process_alert(json_data):
    global NETWORK_DEFINITION
    rule_id = json_data.get("rule").get("id")
    alert_classification = get_alert_classification(json_data=json_data)
    if alert_classification:
        if not check_alert_being_processed(alert_classification):
            log(f"-- [INFO] ALERT RECOGNIZED!", json.dumps(alert_classification, indent=4, default=str))
            log("-- [INFO] ALERT DESCRIPTION", json.dumps(json_data, indent=4, default=str))
            
            register_alert(alert=alert_classification)
            
            # Get network definition
            load_network_definition()

            # Create alert object
            alert = Alert(alert_raw_data=json_data, alert_classification=alert_classification, network_data=NETWORK_DEFINITION)
            generated_prompt = alert.generate_prompt()
            log("-- [INFO] GENERATED PROMPT", generated_prompt)

            # TODO (rmagan): hacer un prompt específico para que me de detalles sobre la alerta

            # Call LLM API to get response
            gemini = Gemini()
            response = gemini.send_prompt(model="gemini-2.5-flash", prompt=generated_prompt)
            playbook_name = generate_playbook_name2(destination=alert.agent_name, alert_type=alert_classification.get("type"))
            playbook_content = response.text
            write_response(playbook_name, response=playbook_content)
            log("-- [INFO] GENERATED PLAYBOOK", playbook_content)

            # Run the playbook using ansible_runner
            if confirm():
                print("-- [INFO] EXECUTING ANSIBLE PLAYBOOK...")
                r = ansible_runner.run(
                    private_data_dir=ANSIBLE_PRIVATE_DATA_DIR,
                    playbook=playbook_name
                )
                print("Status:", r.status)
                print("RC:", r.rc)
                print("Stdout:")
                print(r.stdout.read())
            else:
                print("-- [INFO] OPERATION CANCELLED")
            
            delete_alert(alert=alert_classification)


@app.route('/health', methods=['GET'])
def health_check():
    return "Alive!", 200

@app.route('/alert', methods=['POST'])
def alert():
    json_data = request.get_json()

    if not json_data:
        return jsonify({'error': 'Invalid JSON'}), 400

    process_alert(json_data=json_data)

    return jsonify({'status': 'alert received'}), 200

if __name__ == '__main__':
    app.run(debug=True, host=HOST, port=PORT)