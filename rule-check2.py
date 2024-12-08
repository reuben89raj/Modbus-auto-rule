from z3 import *
import time

# Variables
src_ip = Int('src_ip')
dst_ip = Int('dst_ip')
func_code = Int('func_code')
src_port = Int('src_port')
dst_port = Int('dst_port')

# Configuration: Specify number of IPs, ports, and function codes
num_master_ips = 30
num_slave_ips = 30
num_allowed_ports = 30
num_allowed_func_codes = 40

# Starting base numbers
base_master_ip = 19216811
base_slave_ip = 19216821
base_port = 502
base_func_code = 1

# Dynamically generate lists
master_ips = [base_master_ip + i for i in range(num_master_ips)]
slave_ips = [base_slave_ip + i for i in range(num_slave_ips)]
allowed_ports = [base_port + i for i in range(num_allowed_ports)]
allowed_func_codes = [base_func_code + i for i in range(num_allowed_func_codes)]

# Print the generated lists for reference
#print("Master IPs:", master_ips)
#print("Slave IPs:", slave_ips)
#print("Allowed Ports:", allowed_ports)
#print("Allowed Function Codes:", allowed_func_codes)

# Initialize a solver and a list to store existing rules
s = Solver()
existing_rules = []

# Add initial constraints for valid ranges
s.add(Or([src_ip == ip for ip in master_ips + slave_ips]))
s.add(Or([dst_ip == ip for ip in master_ips + slave_ips]))
s.add(Or([func_code == code for code in allowed_func_codes]))
s.add(Or([dst_port == port for port in allowed_ports]))
s.add(Or([src_port == port for port in allowed_ports]))

# Add default policies
s.add(Implies(Or([src_ip == ip for ip in master_ips]), Or([dst_ip == ip for ip in slave_ips])))
s.add(Implies(Or([src_ip == ip for ip in slave_ips]), Or([dst_ip == ip for ip in master_ips])))

# Add and check rules
def add_rule(rule):
    """Adds a new rule and checks for conflicts or redundancies."""
    # Create a temporary solver to check conflicts
    temp_solver = Solver()
    temp_solver.add(existing_rules)  # Add all existing rules
    temp_solver.add(rule)           # Add the new rule

    # Check for conflicts
    if temp_solver.check() == unsat:
        print("Conflict detected with existing rules.")
        return False

    # Add the rule to the global list and solver if no conflict
    existing_rules.append(rule)
    s.add(rule)
    print("Rule added successfully.")
    return True

def check_rule_uniqueness(rule):
    """Check if a rule already exists or is redundant."""
    t1=time.time()
    temp_solver = Solver()
    temp_solver.add(existing_rules)  # Add all existing rules
    temp_solver.add(Not(rule))       # Add negation of the rule to check for redundancy

    if temp_solver.check() == unsat:
        print("Rule is redundant or already implied by existing rules.")
        t2=time.time()
        print(str("Time to check rule uniqueness: {:0.2f}".format(1000 * (t2 - t1))) + " ms")
        return False
    else:
        t2=time.time()
        print("Rule is not redundant. It is new and unique.")
        print(str("Time to check rule uniqueness: {:0.2f}".format(1000 * (t2 - t1))) + " ms")
        return True

def check_rule_violation(input_src_ip, input_dst_ip, input_src_port, input_dst_port, input_func_code):
    """Check if a specific combination violates any existing rules."""
    t1=time.time()
    test_solver = Solver()
    test_solver.add(s.assertions())  # Add all policy constraints
    test_solver.add(src_ip == input_src_ip)
    test_solver.add(dst_ip == input_dst_ip)
    test_solver.add(src_port == input_src_port)
    test_solver.add(dst_port == input_dst_port)
    test_solver.add(func_code == input_func_code)

    if test_solver.check() == sat:
        t2=time.time()
        
        print("The input rule satisfies all policies.")
        print(str("Time to check rule violation: {:0.2f}".format(1000 * (t2 - t1))) + " ms")
    else:
        t2=time.time()
        
        print("Violation detected for the input rule.")
        print(str("Time to check rule violation: {:0.2f}".format(1000 * (t2 - t1))) + " ms")

# Example rules
rule1 = Or([src_ip == ip for ip in master_ips])
rule2 = Or([dst_ip == ip for ip in slave_ips])
rule3 = And(src_ip == 19216811, dst_ip == 19216821, dst_port == 502, func_code == 1)

# Add and check rules
add_rule(rule1)
add_rule(rule2)
check_rule_uniqueness(rule3)  # Check if rule3 is redundant
add_rule(rule3)
check_rule_uniqueness(rule3) # Re-check rule3
check_rule_violation(19216811, 19216821, 502, 1234, 1)  # Check specific rule
