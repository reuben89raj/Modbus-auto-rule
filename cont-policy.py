import os
import sys
import socket
import json
import struct
import readline

SDE_INSTALL   = os.environ['SDE_INSTALL']
SDE_PYTHON2   = os.path.join(SDE_INSTALL, 'lib', 'python2.7', 'site-packages')
sys.path.append(SDE_PYTHON2)
sys.path.append(os.path.join(SDE_PYTHON2, 'tofino'))

PYTHON3_VER   = '{}.{}'.format(
    sys.version_info.major,
    sys.version_info.minor)
SDE_PYTHON3   = os.path.join(SDE_INSTALL, 'lib', 'python' + PYTHON3_VER,
                             'site-packages')
sys.path.append(SDE_PYTHON3)
sys.path.append(os.path.join(SDE_PYTHON3, 'tofino'))
sys.path.append(os.path.join(SDE_PYTHON3, 'tofino', 'bfrt_grpc'))
import bfrt_grpc.client as gc

# Utility Functions
def ip_to_int(ip_str):
    """Convert IP string to integer."""
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]

def complete_json_files(text, state):
    """Autocomplete JSON file names for user input."""
    files = os.listdir(".")
    matches = [f for f in files if f.startswith(text) and f.endswith(".json")]
    return matches[state] if state < len(matches) else None

readline.set_completer(complete_json_files)
readline.parse_and_bind("tab: complete")

# Initialize gRPC client
for bfrt_client_id in range(10):
    try:
        interface = gc.ClientInterface(
            grpc_addr='localhost:50052',
            client_id=bfrt_client_id,
            device_id=0,
            num_tries=1
        )
        print(f"Connected to BF Runtime Server as client {bfrt_client_id}")
        break
    except:
        print("Could not connect to BF Runtime server. Retrying...")
        quit()

bfrt_info = interface.bfrt_info_get()
program_name = bfrt_info.p4_name_get()
print(f"The target runs the program {program_name}")
interface.bind_pipeline_config(program_name)

# BFRT Table Setup
dev_tgt = gc.Target(0)
flow_table = bfrt_info.table_get("SwitchIngress.flowout")
flow_table.info.key_field_annotation_add("hdr.ipv4.dstAddr", "ipv4")
flow_table.info.key_field_annotation_add("hdr.ipv4.srcAddr", "ipv4")

# Global Set to Track Applied Keys
applied_table_keys = set()

# Graph Representation
def construct_and_print_graph(device_config):
    """Construct and print the network graph."""
    graph = {}
    devices = device_config["Devices"]

    for device in devices:
        if device["Type"].lower() == "master":
            graph[device["Name"]] = {"Slaves": []}
        elif device["Type"].lower() == "slave":
            graph[device["Name"]] = {"ListeningPorts": device.get("ListeningPorts", [])}

    print("\nNetwork Graph:")
    for node, connections in graph.items():
        print(f"{node}: {connections}")
    print()

# Apply Device Modifications
def apply_device_modifications(device_config, data):
    devices = device_config["Devices"]

    for rule in data.get("rules", []):
        action = rule.get("action", "").lower()

        if action == "add_device":
            new_dev = {
                "Type": rule["Type"],
                "IP": rule["IP"],
                "Name": rule["Name"]
            }
            if "ListeningPorts" in rule and rule["Type"].lower() == "slave":
                new_dev["ListeningPorts"] = rule["ListeningPorts"]
            devices.append(new_dev)
            print(new_dev)

        elif action == "remove_device":
            dev_name = rule["Name"]
            device_config["Devices"] = [d for d in devices if d["Name"] != dev_name]

        elif action == "add_ports":
            dev_name = rule["Name"]
            new_ports = rule.get("Ports", [])
            for d in devices:
                if d["Name"] == dev_name and d["Type"].lower() == "slave":
                    if "ListeningPorts" not in d:
                        d["ListeningPorts"] = []
                    d["ListeningPorts"].extend([p for p in new_ports if p not in d["ListeningPorts"]])

        elif action == "remove_ports":
            dev_name = rule["Name"]
            remove_ports = rule.get("Ports", [])
            for d in devices:
                if d["Name"] == dev_name and d["Type"].lower() == "slave":
                    d["ListeningPorts"] = [p for p in d["ListeningPorts"] if p not in remove_ports]

# Construct and Apply Policy Rules
def construct_and_apply_rules(device_config, policies):
    devices = device_config["Devices"]
    masters = [dev for dev in devices if dev["Type"].lower() == "master"]
    slaves = [dev for dev in devices if dev["Type"].lower() == "slave"]

    for policy in policies:
        for rule in policy.get("rules", []):
            master_node = rule.get("master_node", "all")
            slave_node = rule.get("slave_node", "all")
            action = rule.get("action", "").lower()

            if action in ["allow", "deny"]:
                for master in masters if master_node == "all" else [m for m in masters if m["Name"] == master_node]:
                    for slave in slaves if slave_node == "all" else [s for s in slaves if s["Name"] == slave_node]:
                        for port in slave.get("ListeningPorts", []):
                            match_fields = {
                                "hdr.ipv4.dstAddr": ip_to_int(slave["IP"]),
                                "hdr.ipv4.srcAddr": ip_to_int(master["IP"]),
                                "hdr.ipv4.protocol": 6,  # TCP
                                "hdr.tcp.dstPort": int(port)
                            }

                            # Avoid re-adding existing rules
                            key_tuple = tuple(match_fields.items())
                            if action == "allow" and key_tuple in applied_table_keys:
                                continue

                            try:
                                table_key = flow_table.make_key([
                                    gc.KeyTuple(k, v) for k, v in match_fields.items()
                                ])

                                if action == "allow":
                                    table_action = flow_table.make_data([], "SwitchIngress.nop")
                                    flow_table.entry_add(dev_tgt, [table_key], [table_action])
                                    applied_table_keys.add(key_tuple)
                                    print(f"Rule added: src: {master['IP']}, dst: {slave['IP']}, port: {port}")

                                elif action == "deny":
                                    flow_table.entry_del(dev_tgt, [table_key])
                                    applied_table_keys.discard(key_tuple)
                                    print(f"Rule denied: src: {master['IP']}, dst: {slave['IP']}, port: {port}")

                            except Exception as e:
                                print(f"Error applying rule: {rule}. Error: {e}")

# Update Policy
def update_policy(policy):
    construct_and_apply_rules(device_config, [policy])

# Main Loop for Listening and Updating
def listen_and_update_graph(device_config, initial_policy):
    # Install initial table entries
    construct_and_apply_rules(device_config, [initial_policy])
    construct_and_print_graph(device_config)

    while True:
        user_input = input("Enter device config or policy JSON file name, or type 'exit':\n")
        if user_input.strip().lower() == "exit":
            print("Exiting...")
            break

        try:
            with open(user_input.strip(), "r") as file:
                data = json.load(file)

            if "master_node" in data.get("rules", [{}][0]):
                print("\nApplying policy update...")
                update_policy(data)
            elif "action" in data.get("rules", [{}][0]):
                print("\nApplying device configuration update...")
                apply_device_modifications(device_config, data)
                construct_and_apply_rules(device_config, [initial_policy])

            construct_and_print_graph(device_config)

        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"Error loading JSON file: {e}. Please try again.")

# Example Configurations
device_config_json = """{
  "Devices": [
    { "Type": "Master", "IP": "10.0.1.1", "Name": "M1" },
    { "Type": "Master", "IP": "10.0.1.2", "Name": "M2" },
    { "Type": "Slave", "IP": "10.0.2.1", "ListeningPorts": ["502", "503"], "Name": "R1" },
    { "Type": "Slave", "IP": "10.0.2.2", "ListeningPorts": ["502", "503"], "Name": "R2" }
  ]
}"""

initial_policy_json = """{
  "policy_name": "Default Allow All",
  "rules": [
    { "master_node": "all", "slave_node": "all", "action": "allow" }
  ]
}"""

device_config = json.loads(device_config_json)
initial_policy = json.loads(initial_policy_json)
construct_and_print_graph(device_config)
listen_and_update_graph(device_config, initial_policy)
