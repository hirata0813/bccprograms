#!/usr/bin/python3  
from bcc import BPF
from time import sleep

cgroup_procs_file = "/sys/fs/cgroup/my_cgroup/cgroup.procs"


while True:
    sleep(0.01)
    with open(cgroup_procs_file, 'r') as f:
        for cgid in f:
            print(cgid)
    print("----")
