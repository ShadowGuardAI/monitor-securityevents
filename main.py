import argparse
import logging
import sys
import time
import xml.etree.ElementTree as ET

import psutil
import win32evtlog
import win32evtlogutil
import win32security

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define constants
SECURITY_LOG = "Security"

def setup_argparse():
    """
    Sets up the argument parser for the script.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Monitors the Windows Security Event Log for specific events.")
    parser.add_argument("--event-id", type=int, help="Filter events by Event ID.")
    parser.add_argument("--source", type=str, help="Filter events by event source (e.g., Microsoft-Windows-Security-Auditing).")
    parser.add_argument("--user", type=str, help="Filter events by user account name (e.g., DOMAIN\\username).")
    parser.add_argument("--interval", type=int, default=60, help="The interval (in seconds) to check for new events.  Defaults to 60 seconds.")
    parser.add_argument("--persist", action="store_true", help="Keep running and monitoring the event log indefinitely.")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    return parser

def get_security_event_log(event_id=None, source=None, user=None):
    """
    Monitors the Windows Security Event Log for specific events.

    Args:
        event_id (int, optional): Filter events by Event ID. Defaults to None.
        source (str, optional): Filter events by event source. Defaults to None.
        user (str, optional): Filter events by user account name. Defaults to None.

    Yields:
        tuple: A tuple containing the event time, event ID, event source, and event message.
    """
    try:
        # Open the Security Event Log
        hand = win32evtlog.OpenEventLog(None, SECURITY_LOG)  # Using None for local machine
        total = win32evtlog.GetNumberOfEventLogRecords(hand)
        logging.info(f"Total events in Security Log: {total}")

        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        # Read events from the log
        events = win32evtlog.ReadEventLog(hand, flags, 0)

        while events:
            for event in events:
                try:
                    event_time = event.TimeGenerated.Format()
                    event_id_val = event.EventID & 0x3FFFFFFF # mask out top bits
                    event_source = event.SourceName
                    
                    # Get user sid
                    user_sid = None
                    try:
                        for str_val in event.StringInserts:
                            if "S-" in str_val:
                                user_sid = str_val
                                break
                    except Exception as e:
                        logging.warning(f"Error getting SID from event: {e}")
                                
                    user_account = None
                    try:
                        if user_sid:
                            user_account = win32security.LookupAccountSid(None, user_sid)[0]
                    except Exception as e:
                        logging.warning(f"Error looking up user account: {e}")


                    # Convert to XML for easier parsing
                    xml_string = win32evtlogutil.SafeFormatMessage(event, SECURITY_LOG)
                    root = ET.fromstring(xml_string)
                    event_message = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}Data[@Name='SubjectUserName']").text
                    
                    # Apply filters
                    if event_id is not None and event_id_val != event_id:
                        continue
                    if source is not None and event_source != source:
                        continue
                    if user is not None and user_account != user:
                        continue

                    yield event_time, event_id_val, event_source, event_message

                except Exception as e:
                    logging.error(f"Error processing event: {e}")
            
            events = win32evtlog.ReadEventLog(hand, flags, 0)

    except Exception as e:
        logging.error(f"Error accessing event log: {e}")
    finally:
        try:
            win32evtlog.CloseEventLog(hand)
        except Exception as e:
            logging.warning(f"Error closing event log: {e}") #Non-critical

def main():
    """
    Main function to execute the script.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Debug mode enabled.")
    
    logging.info("Starting Security Event Log monitor...")

    try:
        while True:
            for event_time, event_id, event_source, event_message in get_security_event_log(args.event_id, args.source, args.user):
                print(f"Time: {event_time}, Event ID: {event_id}, Source: {event_source}, User: {event_message}")

            if not args.persist:
                break

            logging.info(f"Sleeping for {args.interval} seconds...")
            time.sleep(args.interval)

    except KeyboardInterrupt:
        logging.info("Exiting program.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
    finally:
        logging.info("Security Event Log monitor stopped.")


if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Monitor all events: python monitor-securityevents.py
# 2. Monitor for a specific Event ID: python monitor-securityevents.py --event-id 4624
# 3. Monitor for a specific Source: python monitor-securityevents.py --source "Microsoft-Windows-Security-Auditing"
# 4. Monitor for a specific User: python monitor-securityevents.py --user "DOMAIN\username"
# 5. Monitor and keep running: python monitor-securityevents.py --persist
# 6. Enable debug logging: python monitor-securityevents.py --debug

# Offensive Tool Steps:
# 1. Detect specific attack patterns by monitoring for relevant Event IDs (e.g., 4624, 4625, 4776 for credential access).
# 2. Identify suspicious user activity by monitoring for unusual logon patterns or privilege escalations.
# 3. Track lateral movement by monitoring for network logon events (Event ID 4624 with Logon Type 3) across different systems.
# 4. Monitor for malware execution by tracking specific process creation events (Event ID 4688).
# 5. Detect tampering with security logs by monitoring for events related to log clearing or modification (Event IDs 1102, 104).