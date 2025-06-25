# LLM Network Analyzer

This project analyzes Suricata `eve.json` network logs using a local Large Language Model (LLM) via the Ollama API. It parses DNS, HTTP, and alert events, summarizes findings, and provides a concise security report.

## How it works
- Parses Suricata `eve.json` logs for relevant events
- Formats the data and sends it to a local LLM (Ollama)
- Outputs a human-readable summary of network activity and potential threats

## Usage
1. Place your Suricata `eve.json` log file in a known location.
2. Run the analyzer:
   ```bash
   ./run_analyzer.sh /path/to/eve.json
   ```
3. The script will print a summary to the console.

## Requirements
- Python 3.8+
- [Ollama](https://ollama.com/) running locally
- Suricata logs in `eve.json` format

## Project Structure
- `analyze_traffic.py`: Main CLI tool
- `run_analyzer.sh`: Shell wrapper for easy execution
- `config.yaml`: (To be implemented) Configuration file for model and API settings
- `tests/`: Directory for test logs and future test scripts 