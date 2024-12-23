import json
import os
import readline

def complete_json_files(text, state):
    # Get a list of all files in the current directory
    files = os.listdir(".")
    # Filter files based on the text and ensure they end with .json
    matches = [f for f in files if f.startswith(text) and f.endswith(".json")]
    # Return the state-th match or None if out of bounds
    return matches[state] if state < len(matches) else None

readline.set_completer(complete_json_files)
readline.parse_and_bind("tab: complete")

def apply_device_modifications(device_config, policy):
    """
    Apply modifications to the device_config based on special rules:
    - add_device
    - remove_device
    - add_ports
    - remove_ports

    Each rule in the policy may have one of these actions.
    """
    devices = device_config["Devices"]

    for rule in policy.get("rules", []):
        action = rule.get("action", "").lower()

        if action == "add_device":
            # Expected fields: Type, IP, Name; Optionally ListeningPorts if Slave
            new_dev = {
                "Type": rule["Type"],
                "IP": rule["IP"],
                "Name": rule["Name"]
            }
            if "ListeningPorts" in rule and rule["Type"].lower() == "slave":
                new_dev["ListeningPorts"] = rule["ListeningPorts"]
            devices.append(new_dev)

        elif action == "remove_device":
            # Remove device by Name
            dev_name = rule["Name"]
            device_config["Devices"] = [d for d in devices if d["Name"] != dev_name]

        elif action == "add_ports":
            # Add ports to a given Slave device
            dev_name = rule["Name"]
            new_ports = rule.get("Ports", [])
            for d in devices:
                if d["Name"] == dev_name and d["Type"].lower() == "slave":
                    if "ListeningPorts" not in d:
                        d["ListeningPorts"] = []
                    # Add ports that aren't already there
                    for p in new_ports:
                        if p not in d["ListeningPorts"]:
                            d["ListeningPorts"].append(p)

        elif action == "remove_ports":
            # Remove certain ports from a Slave
            dev_name = rule["Name"]
            remove_ports = rule.get("Ports", [])
            for d in devices:
                if d["Name"] == dev_name and d["Type"].lower() == "slave":
                    if "ListeningPorts" in d:
                        d["ListeningPorts"] = [p for p in d["ListeningPorts"] if p not in remove_ports]

        # If the action is "allow" or "deny", we don't modify the device_config, that comes later.


def construct_and_print_graph(device_config, policy_json):
    # Parse device config
    devices = device_config["Devices"]
    function_codes = device_config["FunctionCodes"]

    # Extract node lists
    master_nodes = [dev["Name"] for dev in devices if dev["Type"].lower() == "master"]
    slave_nodes = [dev["Name"] for dev in devices if dev["Type"].lower() == "slave"]

    # Collect all function codes
    function_code_nodes = [f"FC{code}" for code in function_codes]

    # Create initial graph
    graph = {}

    # Masters connect to all slaves by default
    for master in master_nodes:
        graph[master] = set(slave_nodes)

    # For each slave, assign only its own ports
    for dev in devices:
        if dev["Type"].lower() == "slave":
            # Assign the ports of this specific slave
            slave_name = dev["Name"]
            slave_ports = dev.get("ListeningPorts", [])
            graph[slave_name] = set(slave_ports)

    # Now, for each port found in any slave, map it to all function codes
    # Get a unique set of all ports currently known
    all_ports = {port for dev in devices if dev.get("ListeningPorts") for port in dev["ListeningPorts"]}
    for port in all_ports:
        graph[port] = set(function_code_nodes)

    # Parse and apply connectivity policies (allow/deny)
    for policy in policy_json:
        for rule in policy.get("rules", []):
            action = rule.get("action", "").lower()
            if action in ["allow", "deny"]:
                master = rule["master_node"]
                slave = rule["slave_node"]

                # Handle "all" for masters or slaves
                master_targets = master_nodes if master == "all" else [master]
                slave_targets = slave_nodes if slave == "all" else [slave]

                if action == "allow":
                    # Ensure edges exist
                    for m in master_targets:
                        if m in graph:
                            graph[m].update(slave_targets)
                elif action == "deny":
                    # Remove edges
                    for m in master_targets:
                        if m in graph:
                            graph[m] = graph[m] - set(slave_targets)

    # Print the graph
    print("\nNetwork Graph:")
    for node, connections in graph.items():
        print(f"{node}: {', '.join(sorted(connections))}")


def listen_and_update_graph(device_config, initial_policy):
    policy_rules = [initial_policy]

    while True:
        # Construct and print the graph based on current device_config and policy_rules
        construct_and_print_graph(device_config, policy_rules)

        # Listen for user input
        user_input = input("Enter policy JSON file name or type 'exit' to quit:\n")
        if user_input.strip().lower() == "exit":
            print("Exiting...")
            break

        try:
            with open(user_input.strip(), "r") as file:
                new_policy = json.load(file)
                # First, apply device modifications if any
                apply_device_modifications(device_config, new_policy)
                # Then add the new policy
                policy_rules.append(new_policy)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"Error loading JSON file: {e}. Please try again.")


# Example Usage
device_config_json = """{
  "Devices": [
    { "Type": "Master", "IP": "10.0.1.1", "Name": "M1" },
    { "Type": "Master", "IP": "10.0.1.2", "Name": "M2" },
    { "Type": "Slave", "IP": "10.0.2.1", "ListeningPorts": ["502", "503"], "Name": "R1" },
    { "Type": "Slave", "IP": "10.0.2.2", "ListeningPorts": ["502", "503"], "Name": "R2" }
  ],
  "FunctionCodes": [1, 4, 8, 15],
  "Links": ["M1-S1", "M2-S1", "R1-S3", "R2-S4"]
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
