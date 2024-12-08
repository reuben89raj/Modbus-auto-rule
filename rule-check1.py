from z3 import *
import time

# Variables
src_ip = Int('src_ip')
dst_ip = Int('dst_ip')
func_code = Int('func_code')
src_port = Int('src_port')
dst_port = Int('dst_port')

# Configuration: Specify number of IPs, ports, and function codes
num_master_ips = 3
num_slave_ips = 3
num_allowed_ports = 3  # Example: More than one port
num_allowed_func_codes = 4

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
print("Master IPs:", master_ips)
print("Slave IPs:", slave_ips)
print("Allowed Ports:", allowed_ports)
print("Allowed Function Codes:", allowed_func_codes)

# Solver instance
s = Solver()

# Add constraints for valid master and slave IPs
s.add(Or([src_ip == ip for ip in master_ips + slave_ips]))
s.add(Or([dst_ip == ip for ip in master_ips + slave_ips]))

# Policy: Only master can initiate requests
s.add(Implies(Or([src_ip == ip for ip in master_ips]), Or([dst_ip == ip for ip in slave_ips])))

# Policy: Slaves do not talk to each other
s.add(Implies(Or([src_ip == ip for ip in slave_ips]), Or([dst_ip == ip for ip in master_ips])))

# Policy: Allowed destination ports for requests
s.add(Implies(Or([src_ip == ip for ip in master_ips]), Or([dst_port == port for port in allowed_ports])))

# Policy: Allowed source ports for responses
s.add(Implies(Or([src_ip == ip for ip in slave_ips]), Or([src_port == port for port in allowed_ports])))

# Policy: Only allowed function codes
s.add(Or([func_code == code for code in allowed_func_codes]))

for constraint in s.assertions():
    print(constraint)
# Function to check a specific rule
def check_rule(input_src_ip, input_dst_ip, input_src_port, input_dst_port, input_func_code):
    t1 = time.time()
    test_solver = Solver()
    test_solver.add(s.assertions())  # Add all policy constraints
    test_solver.add(src_ip == input_src_ip)
    test_solver.add(dst_ip == input_dst_ip)
    test_solver.add(src_port == input_src_port)
    test_solver.add(dst_port == input_dst_port)
    test_solver.add(func_code == input_func_code)

    if test_solver.check() == sat:
        print("The input rule satisfies all policies.")
    else:
        print("Violation detected for the input rule.")
    t2 = time.time()
    print(str("{:0.2f}".format(1000 * (t2 - t1))) + " ms")

# Example: Check a specific rule



#check_rule(19216811, 19216823, 1234, 502, 1)
#check_rule(19216811, 19216823, 1234, 502, 1)
#check_rule(19216811, 19216823, 1234, 502, 1)
#check_rule(19216811, 19216823, 1234, 502, 1)
#check_rule(19216811, 19216823, 1234, 502, 1)



