# Configuration for mini-siem 

# Event IDs to monitor

SECURITY_EVENT_IDS = [4624, 4625, 4672, 4688, 4720, 4732]
SYSTEM_EVENT_IDS = [6005, 6006, 41, 600]
#the id 600 inside system is temperory id for testing purposes and will be removed later

# Polling interval (in seconds for real-time monitoring)
POLL_INTERVAL = 5

# Database file path
DB_PATH = "data/mini_siem.db"

MAX_EVENTS = 50

DEBUG = True
