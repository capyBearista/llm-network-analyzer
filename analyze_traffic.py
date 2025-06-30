#!/usr/bin/env python3
import ollama      # communicate with ollama
import argparse    # parse command line arguments
import json        # JSON functions
import yaml        # enable loading of config.yaml
import os          # enable checking for config.yaml

# --- Configuration ---
# Default config values if config.yaml is missing or incomplete
DEFAULT_CONFIG = {
    'model_name': 'deepseek-r1:7b',
    'ollama_endpoint': 'http://localhost:11434'
}

def load_config(config_path='config.yaml'):
    """Load configuration from a YAML file, with defaults and error handling."""
    config = DEFAULT_CONFIG.copy()
    if not os.path.exists(config_path):
        print(f"Warning: {config_path} not found. Using default configuration.")
        return config
    try:
        with open(config_path, 'r') as f:
            user_config = yaml.safe_load(f) or {}
            config.update(user_config)
    except Exception as e:
        print(f"Error loading {config_path}: {e}. Using default configuration.")
    return config

# Load config and set model/endpoint variables
config = load_config()
MODEL_NAME = config['model_name']
OLLAMA_ENDPOINT = config['ollama_endpoint']

# import ollama
# ollama.base_url = OLLAMA_ENDPOINT
import ollama


def generate_system_prompt():
    """Creates the initial instruction for the LLM."""
    return """
    You are a helpful network security analyst. Your task is to analyze network event logs from Suricata.
    The user will provide a summary of recent events. Provide a concise, bullet-pointed summary of your findings.
    Focus on:
    - Suspicious DNS lookups (e.g., to known malicious domains, or unusual domain names).
    - HTTP traffic to strange hostnames.
    - Any security alerts that have fired.
    - Any other activity that deviates from typical home network behavior.
    If the logs appear normal and uninteresting, state that clearly.
    """


def parse_eve_log(log_content: str):
    """Parses the raw eve.json lines and extracts key information."""
    parsed_events = []
    for line in log_content.strip().split('\n'):
        try:
            event = json.loads(line)
            event_type = event.get('event_type')
            summary = f"[{event.get('timestamp')}] "

            # Extract and summarize DNS, HTTP, and alert events
            if event_type == 'dns':
                query = event.get('dns', {}).get('rrname', 'N/A')
                summary += f"DNS Query for: {query}"
                parsed_events.append(summary)
            elif event_type == 'http':
                hostname = event.get('http', {}).get('hostname', 'N/A')
                url = event.get('http', {}).get('url', 'N/A')
                summary += f"HTTP Request to: {hostname}{url}"
                parsed_events.append(summary)
            elif event_type == 'alert':
                alert_sig = event.get('alert', {}).get('signature', 'N/A')
                src = event.get('src_ip', 'N/A')
                dest = event.get('dest_ip', 'N/A')
                summary += f"ALERT: {alert_sig} from {src} to {dest}"
                parsed_events.append(summary)

        except json.JSONDecodeError:
            continue  # Skip lines that are not valid JSON

    return "\n".join(parsed_events)


def analyze_log_content(formatted_log_data: str):
    """Sends the formatted log data to the Ollama API for analysis."""
    if not formatted_log_data:
        return "No relevant DNS, HTTP, or Alert events found in the log sample."

    print(f"🤖 Contacting LLM ({MODEL_NAME})... Please hold, this might take a while!")
    try:
        response = ollama.chat(
            model=MODEL_NAME,
            messages=[
                {'role': 'system', 'content': generate_system_prompt()},
                {'role': 'user', 'content': f"Please analyze the following summary of recent network events:\n\n---\n{formatted_log_data}\n---"},
            ]
        )
        return response['message']['content']
    except Exception as e:
        return f"Error contacting Ollama API: {e}"


def main():
    """Main function to run the script."""
    parser = argparse.ArgumentParser(description="Analyze a Suricata eve.json log file using a local LLM.")
    parser.add_argument("logfile", help="Path to the eve.json log file (e.g., /var/log/suricata/eve.json)")
    args = parser.parse_args()

    try:
        print(f"📖 Reading log file: {args.logfile}")
        with open(args.logfile, 'r') as f:
            lines = f.readlines()
            log_chunk = "".join(lines[-100:])  # Only analyze the last 100 lines for efficiency

        formatted_data = parse_eve_log(log_chunk)  # Extract relevant events
        analysis = analyze_log_content(formatted_data)  # Get LLM analysis

        print("\n--- 🕵️ LLM Analysis Report ---")
        print(analysis)
        print("----------------------------\n")

    except FileNotFoundError:
        print(f"Error: File not found at {args.logfile}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
