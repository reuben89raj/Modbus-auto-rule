import networkx as nx
import json

# Graph Construction
def construct_graph(device_config, policy_json):
    # Parse device config
    devices = device_config["Devices"]
    function_codes = device_config["FunctionCodes"]

    # Initialize graph
    G = nx.DiGraph()

    # Add nodes for Masters and Slaves
    master_nodes = [dev["Name"] for dev in devices if dev["Type"] == "Master"]
    slave_nodes = [dev["Name"] for dev in devices if dev["Type"] == "Slave"]
    ports = list(set(port for dev in devices if "ListeningPorts" in dev for port in dev["ListeningPorts"]))
    function_code_nodes = [f"FC{code}" for code in function_codes]

    # Add nodes to the graph
    G.add_nodes_from(master_nodes, level="Master")
    G.add_nodes_from(slave_nodes, level="Slave")
    G.add_nodes_from(ports, level="Port")
    G.add_nodes_from(function_code_nodes, level="FunctionCode")

    # Create full-mesh connectivity
    for master in master_nodes:
        for slave in slave_nodes:
            G.add_edge(master, slave)
    for slave in slave_nodes:
        for port in ports:
            G.add_edge(slave, port)
    for port in ports:
        for fc in function_code_nodes:
            G.add_edge(port, fc)

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
                    for s in slave_targets:
                        G.add_edge(m, s)
            elif action == "deny":
                # Remove edges
                for m in master_targets:
                    for s in slave_targets:
                        if G.has_edge(m, s):
                            G.remove_edge(m, s)

    return G

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

policy_json = """[
  {
    "policy_name": "Default Allow All",
    "rules": [
      { "master_node": "all", "slave_node": "all", "action": "allow" }
    ]
  },
  {
    "policy_name": "Deny Specific",
    "rules": [
      { "master_node": "M1", "slave_node": "R2", "action": "deny" }
    ]
  }
]"""

device_config = json.loads(device_config_json)
policy_rules = json.loads(policy_json)

G = construct_graph(device_config, policy_rules)
# Visualize or print the graph
print("Edges:", list(G.edges))

