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

def construct_and_print_graph(device_config, policy_json):
    # Parse device config
    devices = device_config["Devices"]
    function_codes = device_config["FunctionCodes"]

    # Initialize graph representation
    graph = {}

    # Add nodes for Masters and Slaves
    master_nodes = [dev["Name"] for dev in devices if dev["Type"] == "Master"]
    slave_nodes = [dev["Name"] for dev in devices if dev["Type"] == "Slave"]
    ports = list(set(port for dev in devices if "ListeningPorts" in dev for port in dev["ListeningPorts"]))
    function_code_nodes = [f"FC{code}" for code in function_codes]

    # Create initial full-mesh connectivity
    for master in master_nodes:
        graph[master] = {slave for slave in slave_nodes}
    for slave in slave_nodes:
        graph[slave] = {port for port in ports}
    for port in ports:
        graph[port] = {fc for fc in function_code_nodes}

    # Parse and apply policies
    for policy in policy_json:
        for rule in policy["rules"]:
            master = rule["master_node"]
            slave = rule["slave_node"]
            action = rule["action"]

            # Handle "all" for masters or slaves
            master_targets = master_nodes if master == "all" else [master]
            slave_targets = slave_nodes if slave == "all" else [slave]

            if action == "allow":
                # Ensure edges exist
                for m in master_targets:
                    graph.setdefault(m, set()).update(slave_targets)
            elif action == "deny":
                # Remove edges
                for m in master_targets:
                    if m in graph:
                        graph[m] = graph[m] - set(slave_targets)

    # Print the graph
    print("Network Graph:")
    for node, connections in graph.items():
        print(f"{node}: {', '.join(connections)}")

def listen_and_update_graph(device_config, initial_policy):
    policy_rules = [initial_policy]

    while True:
        construct_and_print_graph(device_config, policy_rules)

        # Listen for user input
        user_input = input("Enter policy JSON file name or type 'exit' to quit:\n")
        if user_input.strip().lower() == "exit":
            print("Exiting...")
            break

        try:
            with open(user_input.strip(), "r") as file:
                new_policy = json.load(file)
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
