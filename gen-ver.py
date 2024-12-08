import json
import time
from z3 import *

# Z3 Variables
src_ip = Int('src_ip')
dst_ip = Int('dst_ip')
func_code = Int('func_code')
src_port = Int('src_port')
dst_port = Int('dst_port')

# Solver instance
s = Solver()

# Dynamically generate initial values (adjustable parameters)
num_master_ips = 300
num_slave_ips = 300
num_allowed_ports = 200
num_allowed_func_codes = 400
base_master_ip = 19216701
base_slave_ip = 18216801
base_port = 502
base_func_code = 1

master_ips = [base_master_ip + i for i in range(num_master_ips)]
slave_ips = [base_slave_ip + i for i in range(num_slave_ips)]
allowed_ports = [base_port + i for i in range(num_allowed_ports)]
allowed_func_codes = [base_func_code + i for i in range(num_allowed_func_codes)]

# A map from placeholder strings used in JSON to actual Python lists
placeholder_map = {
    "[Master_IPs]": master_ips,
    "[Slave_IPs]": slave_ips,
    "[Allowed_Ports]": allowed_ports,
    "[FUNC_CODEs]": allowed_func_codes
}

# A map from variable names in the policy to the corresponding Z3 variables
var_map = {
    "src_ip": src_ip,
    "dst_ip": dst_ip,
    "src_port": src_port,
    "dst_port": dst_port,
    "func_code": func_code
}

def parse_atomic_condition(cond_str):
    """
    Parse an atomic condition like:
    - "src_ip IN [Master_IPs]"
    - "dst_ip IN [Slave_IPs]"
    - "func_code IN [FUNC_CODEs]"
    - "dst_port IN [Allowed_Ports]"
    
    Returns a Z3 expression.
    """
    cond_str = cond_str.strip()
    parts = cond_str.split()
    if len(parts) != 3:
        raise ValueError(f"Invalid atomic condition format: {cond_str}")

    var_name, operator, list_name = parts
    if operator.upper() != "IN":
        raise ValueError(f"Unsupported operator {operator} in {cond_str}, only IN is supported.")

    if var_name not in var_map:
        raise ValueError(f"Unknown variable {var_name}")
    z3_var = var_map[var_name]

    if list_name not in placeholder_map:
        raise ValueError(f"Unknown placeholder {list_name}")

    allowed_values = placeholder_map[list_name]
    return Or([z3_var == val for val in allowed_values])

def parse_condition(condition):
    """
    Parse a full condition string that may contain AND/OR and atomic conditions.
    """
    # Split on "OR"
    or_blocks = condition.split("OR")
    or_clauses = []
    for or_block in or_blocks:
        and_parts = or_block.split("AND")
        and_clauses = []
        for and_part in and_parts:
            and_part = and_part.strip()
            atomic_expr = parse_atomic_condition(and_part)
            and_clauses.append(atomic_expr)
        
        if len(and_clauses) == 1:
            or_clauses.append(and_clauses[0])
        else:
            or_clauses.append(And(*and_clauses))
    
    if len(or_clauses) == 1:
        return or_clauses[0]
    else:
        return Or(*or_clauses)

def load_policies(policy_json):
    policies = json.loads(policy_json)

    allow_conditions = []
    drop_conditions = []

    for policy in policies:
        print(f"Loading policy: {policy['policy_name']}")
        for rule in policy['rules']:
            z3_condition = parse_condition(rule['condition'])
            if rule['action'].upper() == "ALLOW":
                # Add this to the list of allow conditions
                allow_conditions.append(z3_condition)
            elif rule['action'].upper() == "DROP":
                # Add this to the list of drop conditions
                drop_conditions.append(z3_condition)
            else:
                raise ValueError(f"Unknown action: {rule['action']}")

    # Combine allow rules: Packet must match at least one allow condition
    # If there are no allow conditions, means no packet is allowed
    if allow_conditions:
        s.add(Or(*allow_conditions))
    else:
        # No allow rules? Then no packet is allowed:
        s.add(False)

    # Combine drop conditions: Packet must not match any drop condition
    if drop_conditions:
        s.add(Not(Or(*drop_conditions)))

def check_rule(input_src_ip, input_dst_ip, input_src_port, input_dst_port, input_func_code):
    t1=time.time()
    test_solver = Solver()
    test_solver.add(s.assertions())  # Add all policy constraints
    test_solver.add(src_ip == input_src_ip)
    test_solver.add(dst_ip == input_dst_ip)
    test_solver.add(src_port == input_src_port)
    test_solver.add(dst_port == input_dst_port)
    test_solver.add(func_code == input_func_code)

    if test_solver.check() == sat:
        print(f"Rule ({input_src_ip}, {input_dst_ip}, {input_src_port}, {input_dst_port}, {input_func_code}) satisfies the policies.")
    else:
        print(f"Rule ({input_src_ip}, {input_dst_ip}, {input_src_port}, {input_dst_port}, {input_func_code}) violates the policies.")
    t2=time.time()
    print(str("Time to check rule : {:0.2f}".format(1000 * (t2 - t1))) + " ms")
# Example Policy JSON
policy_json = """
[
    {
        "policy_name": "Only Modbus Initiates Request",
        "rules": [
            {
                "condition": "src_ip IN [Master_IPs] AND dst_ip IN [Slave_IPs] AND dst_port IN [Allowed_Ports]",
                "action": "ALLOW"
            }
        ]
    },
    {
        "policy_name": "Only Slave Sends Response",
        "rules": [
            {
                "condition": "src_ip IN [Slave_IPs] AND dst_ip IN [Master_IPs] AND src_port IN [Allowed_Ports]",
                "action": "ALLOW"
            }
        ]
    },
    {
        "policy_name": "Slaves Do Not Communicate with each other",
        "rules": [
            {
                "condition": "src_ip IN [Slave_IPs] AND dst_ip IN [Slave_IPs]",
                "action": "DROP"
            }
        ]
    },
    {
        "policy_name": "Only Allowed Function Codes",
        "rules": [
            {
                "condition": "func_code IN [FUNC_CODEs]",
                "action": "ALLOW"
            }
        ]
    }
]
"""

# Load policies and add constraints to the solver
load_policies(policy_json)

"""
# Print out constraints
print("Current Solver Constraints:")
for c in s.assertions():
    print(c)
"""
# Example Checks
# This packet: (19216701, 19216801, 2123, 502, 1)
# - src_ip=19216701 (master), dst_ip=19216801 (slave), dst_port=502 (allowed port), func_code=1 (allowed)
# Matches the "Only Modbus Initiates Request" and "Only Allowed Function Codes" ALLOW rules at least.
# No drop conditions triggered.
check_rule(19216701, 182161000, 2123, 502, 1)   # Should now be allowed
check_rule(192161000, 182161000, 2124, 502, 1)
# Another example that likely violates
check_rule(18216821, 18216822, 600, 502, 4)
