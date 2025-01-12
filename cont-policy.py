import os
import sys
import socket
import json
import struct
import readline

# Paths for Python libraries
SDE_INSTALL = os.environ['SDE_INSTALL']
PYTHON3_VER = '{}.{}'.format(sys.version_info.major, sys.version_info.minor)

sys.path.extend([
    os.path.join(SDE_INSTALL, 'lib', 'python2.7', 'site-packages'),
    os.path.join(SDE_INSTALL, 'lib', 'python2.7', 'site-packages', 'tofino'),
    os.path.join(SDE_INSTALL, 'lib', 'python' + PYTHON3_VER, 'site-packages'),
    os.path.join(SDE_INSTALL, 'lib', 'python' + PYTHON3_VER, 'site-packages', 'tofino'),
    os.path.join(SDE_INSTALL, 'lib', 'python' + PYTHON3_VER, 'site-packages', 'tofino', 'bfrt_grpc'),
])

import bfrt_grpc.client as gc  # type: ignore

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

# Graph-to-Table Mapping
graph_to_table = {}

# Graph Representation
def construct_graph(device_config, policies):
    """Construct the graph based on device config and policies."""
    graph = {}
    masters = [dev["Name"] for dev in device_config["Devices"] if dev["Type"].lower() == "master"]
    slaves = [dev for dev in device_config["Devices"] if dev["Type"].lower() == "slave"]

    for master in masters:
        graph[master] = [slave["Name"] for slave in slaves]

    for slave in slaves:
        graph[slave["Name"]] = slave.get("ListeningPorts", [])

    # Apply policies to refine the graph
    for policy in policies:
        for rule in policy.get("rules", []):
            master_node = rule.get("master_node", "all")
            slave_node = rule.get("slave_node", "all")
            action = rule.get("action", "").lower()

            masters = [master for master in graph.keys() if master == master_node or master_node == "all"]
            slaves = [slave for slave in graph if slave in graph and (slave == slave_node or slave_node == "all")]

            if action == "deny":
                for master in masters:
                    graph[master] = [slave for slave in graph[master] if slave not in slaves]

    return graph

def apply_table_entries(graph, device_config, policies):
    """Install flow rules based on the graph."""
    global graph_to_table

    for master, slaves in graph.items():
        for slave_name in slaves:
            slave = next((d for d in device_config["Devices"] if d["Name"] == slave_name), None)
            if not slave:
                continue

            for port in slave.get("ListeningPorts", []):
                match_fields = {
                    "hdr.ipv4.srcAddr": ip_to_int(next((d["IP"] for d in device_config["Devices"] if d["Name"] == master), None)),
                    "hdr.ipv4.dstAddr": ip_to_int(slave["IP"]),
                    "hdr.ipv4.protocol": 6,
                    "hdr.tcp.dstPort": int(port)
                }
                key_tuple = tuple(match_fields.items())

                if key_tuple not in graph_to_table:
                    try:
                        table_key = flow_table.make_key([
                            gc.KeyTuple(k, v) for k, v in match_fields.items()
                        ])
                        table_action = flow_table.make_data([], "SwitchIngress.nop")
                        flow_table.entry_add(dev_tgt, [table_key], [table_action])
                        graph_to_table[key_tuple] = table_key  # Store the actual table_key
                        print(f"Rule added: src: {master}, dst: {slave['Name']}, port: {port}")
                    except Exception as e:
                        print(f"Error adding rule for {master}->{slave['Name']} on port {port}: {e}")


def remove_table_entries(paths, device_config):
    """Remove outdated flow rules."""
    global graph_to_table
    print(f"Paths to remove: {paths}")
    print(f"Device Config: {device_config}")
    for path in paths:
        master, slave, port = path
        slave_device = next((d for d in device_config["Devices"] if d["Name"] == slave), None)
        master_device = next((d for d in device_config["Devices"] if d["Name"] == master), None)
        print(f"slave_device = {slave_device} master_device = {master_device}")
        if not slave_device or not master_device:
            continue

        match_fields = {
            "hdr.ipv4.srcAddr": ip_to_int(master_device["IP"]),
            "hdr.ipv4.dstAddr": ip_to_int(slave_device["IP"]),
            "hdr.ipv4.protocol": 6,
            "hdr.tcp.dstPort": int(port),
        }
        key_tuple = tuple(match_fields.items())
        print(f"Key tuple for deletion: {key_tuple}")
        
        if key_tuple in graph_to_table:
            try:
                flow_table.entry_del(dev_tgt, [graph_to_table[key_tuple]])  # Use the stored table_key
                del graph_to_table[key_tuple]
                print(f"Rule removed: src: {master}, dst: {slave}, port: {port}")
            except Exception as e:
                print(f"Error removing rule: {e}")


def update_device_config(device_config, new_config):
    """Update the device configuration based on the action."""
    removed_devices = []  # Track devices removed from the configuration
    action = new_config.get("action")

    if action == "add_device":
        for device in new_config.get("Devices", []):
            # Avoid duplicates
            if any(dev["Name"] == device["Name"] for dev in device_config["Devices"]):
                print(f"Device {device['Name']} already exists. Skipping addition.")
            else:
                device_config["Devices"].append(device)
                print(f"Device added: {device['Name']}")

    elif action == "remove_device":
        for device in new_config.get("Devices", []):
            existing_device = next((d for d in device_config["Devices"] if d["Name"] == device["Name"]), None)
            if existing_device:
                device_config["Devices"] = [d for d in device_config["Devices"] if d["Name"] != device["Name"]]
                removed_devices.append(device["Name"])
                print(f"Device removed: {device['Name']}")
            else:
                print(f"Device {device['Name']} does not exist. Skipping removal.")

    return removed_devices


def update_policy(policies, new_policy):
    """Update the policy list."""
    policies.append(new_policy)
    print(f"Policy updated: {new_policy['policy_name']}")

def listen_and_update(device_config, policies):
    """Listen for updates and maintain the network graph."""
    graph = construct_graph(device_config, policies)
    apply_table_entries(graph, device_config, policies)
    print_graph(graph)

    while True:
        user_input = input("Enter JSON file name for device config or policy update, or type 'exit':\n")
        if user_input.strip().lower() == "exit":
            print("Exiting...")
            break

        try:
            with open(user_input.strip(), "r") as file:
                data = json.load(file)

            if "device_config_name" in data:
                print("\nUpdating device configuration...")
                # Snapshot the current device configuration
                previous_device_config = json.loads(json.dumps(device_config))  # Deep copy
                previous_graph = construct_graph(previous_device_config, policies)

                # Update the device configuration
                removed_devices = update_device_config(device_config, data)

                # Generate the updated graph after device config change
                graph = construct_graph(device_config, policies)

                # Remove table entries for paths involving removed devices
                removed_paths = [
                    (master, slave, port)
                    for master, slaves in previous_graph.items()
                    for slave in slaves
                    for port in previous_graph.get(slave, [])
                    if slave in removed_devices
                ]
                remove_table_entries(removed_paths, previous_device_config)

                # Apply any new table entries
                apply_table_entries(graph, device_config, policies)
                print_graph(graph)

            elif "policy_name" in data:
                print("\nUpdating policy...")
                previous_graph = graph
                update_policy(policies, data)
                graph = construct_graph(device_config, policies)
                remove_table_entries(graph, previous_graph, device_config)
                apply_table_entries(graph, device_config, policies)

            print_graph(graph)

        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"Error loading JSON file: {e}. Please try again.")

def print_graph(graph):
    """Print the current graph."""
    print("\nNetwork Graph:")
    for master, slaves in graph.items():
        print(f"{master}: {', '.join(slaves)}")

# Example Configurations
device_config_json = """{
  "device_config_name": "Initial Configuration",
  "Devices": [
    { "Type": "Master", "IP": "10.0.1.1", "Name": "M1" },
    { "Type": "Master", "IP": "10.0.1.2", "Name": "M2" },
    { "Type": "Slave", "IP": "10.0.2.1", "ListeningPorts": ["502", "503"], "Name": "R1" },
    { "Type": "Slave", "IP": "10.0.2.2", "ListeningPorts": ["502", "503"], "Name": "R2" }
  ]
}
"""

initial_policy_json = """{
  "policy_name": "Default Allow All",
  "rules": [
    { "master_node": "all", "slave_node": "all", "action": "allow" }
  ]
}"""

device_config = json.loads(device_config_json)
policies = [json.loads(initial_policy_json)]

listen_and_update(device_config, policies)
