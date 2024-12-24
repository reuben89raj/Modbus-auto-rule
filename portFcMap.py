import json
import os
import readline

def complete_json_files(text, state):
    files = os.listdir("./json")
    matches = [f for f in files if f.startswith(text) and f.endswith(".json")]
    return matches[state] if state < len(matches) else None

readline.set_completer(complete_json_files)
readline.parse_and_bind("tab: complete")

def apply_device_modifications(device_config, policy):
    devices = device_config["Devices"]

    for rule in policy.get("rules", []):
        action = rule.get("action", "").lower()

        if action == "add_device":
            new_dev = {
                "Type": rule["Type"],
                "IP": rule["IP"],
                "Name": rule["Name"]
            }
            if "PortFunctionMap" in rule and rule["Type"].lower() == "slave":
                new_dev["PortFunctionMap"] = rule["PortFunctionMap"]
            devices.append(new_dev)

        elif action == "remove_device":
            dev_name = rule["Name"]
            device_config["Devices"] = [d for d in devices if d["Name"] != dev_name]

        elif action == "add_ports":
            dev_name = rule["Name"]
            new_port_func_map = rule.get("PortFunctionMap", {})
            for d in devices:
                if d["Name"] == dev_name and d["Type"].lower() == "slave":
                    if "PortFunctionMap" not in d:
                        d["PortFunctionMap"] = {}
                    d["PortFunctionMap"].update(new_port_func_map)

        elif action == "remove_ports":
            dev_name = rule["Name"]
            remove_ports = rule.get("Ports", [])
            for d in devices:
                if d["Name"] == dev_name and d["Type"].lower() == "slave":
                    if "PortFunctionMap" in d:
                        for port in remove_ports:
                            d["PortFunctionMap"].pop(port, None)

def construct_and_print_graph(device_config, policy_json):
    devices = device_config["Devices"]

    graph = {}

    master_nodes = [dev["Name"] for dev in devices if dev["Type"].lower() == "master"]
    slave_nodes = [dev["Name"] for dev in devices if dev["Type"].lower() == "slave"]

    for master in master_nodes:
        graph[master] = set(slave_nodes)

    for dev in devices:
        if dev["Type"].lower() == "slave":
            slave_name = dev["Name"]
            port_func_map = dev.get("PortFunctionMap", {})
            graph[slave_name] = {}
            for port, functions in port_func_map.items():
                graph[slave_name][port] = set([f"FC{fc}" for fc in functions])

    for policy in policy_json:
        for rule in policy.get("rules", []):
            action = rule.get("action", "").lower()
            if action in ["allow", "deny"]:
                master = rule["master_node"]
                slave = rule["slave_node"]

                master_targets = master_nodes if master == "all" else [master]
                slave_targets = slave_nodes if slave == "all" else [slave]

                if action == "allow":
                    for m in master_targets:
                        if m in graph:
                            graph[m].update(slave_targets)
                elif action == "deny":
                    for m in master_targets:
                        if m in graph:
                            graph[m] = graph[m] - set(slave_targets)

    print("\nNetwork Graph:")
    for node, connections in graph.items():
        if isinstance(connections, dict):
            print(f"{node}:")
            for port, funcs in connections.items():
                print(f"  Port {port}: {', '.join(funcs)}")
        else:
            print(f"{node}: {', '.join(sorted(connections))}")

def listen_and_update_graph(device_config, initial_policy):
    policy_rules = [initial_policy]

    while True:
        construct_and_print_graph(device_config, policy_rules)

        user_input = input("Enter policy JSON file name or type 'exit' to quit:\n").strip()
        if user_input.lower() == "exit":
            print("Exiting...")
            break

        user_input = f"./json/{user_input}"
        try:
            with open(user_input, "r") as file:
                new_policy = json.load(file)
                print(f"Applying policy: {new_policy}")
                apply_device_modifications(device_config, new_policy)
                policy_rules.append(new_policy)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"Error loading JSON file: {e}. Please try again.")

# Example Device Config
device_config_json = """{
  "Devices": [
    { "Type": "Master", "IP": "10.0.1.1", "Name": "M1" },
    { "Type": "Master", "IP": "10.0.1.2", "Name": "M2" },
    { "Type": "Slave", "IP": "10.0.2.1", "Name": "R1", "PortFunctionMap": {
        "502": [1, 4],
        "503": [8, 15]
      }
    },
    { "Type": "Slave", "IP": "10.0.2.2", "Name": "R2", "PortFunctionMap": {
        "502": [1, 8],
        "503": [4, 15]
      }
    }
  ],
  "FunctionCodes": [1, 4, 8, 15]
}"""

initial_policy_json = """{
  "policy_name": "Default Allow All",
  "rules": [
    { "master_node": "all", "slave_node": "all", "action": "allow" }
  ]
}"""

device_config = json.loads(device_config_json)
initial_policy = json.loads(initial_policy_json)

listen_and_update_graph(device_config, initial_policy)
