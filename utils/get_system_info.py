import psutil
import shutil
from typing import Dict, List

def get_system_info():
    # CPU
    cpu_percent = psutil.cpu_percent(interval=1)

    # Memory
    virtual_mem = psutil.virtual_memory()
    mem_total = virtual_mem.total
    mem_used = virtual_mem.used
    mem_percent = virtual_mem.percent

    # Disk (Root summary)
    disk = shutil.disk_usage("/")
    disk_total = disk.total
    disk_used = disk.used
    disk_percent = disk_used / disk_total * 100

    # Disk Partitions
    disk_partition_info = []
    for partition in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            disk_partition_info.append(
                {
                    "device": partition.device,
                    "mountpoint": partition.mountpoint,
                    "fstype": partition.fstype,
                    "total": usage.total,
                    "used": usage.used,
                    "free": usage.free,
                    "percent": usage.percent,
                }
            )
        except (PermissionError, OSError):
            continue  # Skip inaccessible partitions

    return {
        "cpu": {"percent": cpu_percent},
        "memory": {
            "total": mem_total,
            "used": mem_used,
            "percent": mem_percent,
        },
        "disk": {
            "total": disk_total,
            "used": disk_used,
            "percent": disk_percent,
            "partitions": disk_partition_info,
        },
    }
def get_network_interfaces():
    """Get detailed network interface information"""
    interfaces = []
    for name, addrs in psutil.net_if_addrs().items():
        stats = psutil.net_if_stats().get(name)
        interfaces.append(
            {
                "name": name,
                "is_up": stats.isup if stats else False,
                "speed": stats.speed if stats else 0,
            }
        )
    return interfaces