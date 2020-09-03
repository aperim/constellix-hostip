import sys
import time
import json
import datetime
import decimal


def stderr(*a): 
    """Writes to stderr

    Args:
        *a (dict): The data to be written to stderr

    Returns:
        None
    """
    return print(*a, file = sys.stderr)

def stdout(*a): 
    """Writes to stdout

    Args:
        *a (dict): The data to be written to stdout

    Returns:
        None
    """
    return print(*a, file = sys.stdout) 

def jsd(data):
    """Dump the data as pretty JSON to stdout

    Args:
        data (dict): The data to be dumped

    Returns:
        None
    """
    return stdout(json.dumps(data, indent=4, sort_keys=True))

def epoch():
    """Get the currenct epoch in milliseconds

        Args:
            None

        Returns:
            int: The current epoch in milliseconds
    """    
    return int(time.time_ns()/1000000)