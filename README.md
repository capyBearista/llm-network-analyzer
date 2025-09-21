# LLM Network Analyzer

*Analyze Suricata network logs with a local LLM for instant, human-readable security insights.*

### How it works
- Parses Suricata `eve.json` logs for relevant events
- Formats the data and sends it to a local LLM (Ollama)
- Outputs a human-readable summary of network activity and potential threats

Note: The script is set to analyze only the last 100 lines.

### Quick Start

1. Clone the repo:
   ```bash
   git clone https://github.com/yourname/llm-network-analyzer.git
   cd llm-network-analyzer
   ```

2. Install dependencies:
   ```bash
   wip - commands go here :(
   ```

3. Edit `config.yaml`
   - Set your preferred LLM model and Ollama endpoint

4. Run the script:
   ```bash
   ./run_analyzer.sh /path/to/eve.json
   ```

5. *Wait...*

6. Enjoy! (...or be concerned if the LLM picks up issues)


### 🛠Requirements

- Python 3.6+
- [Ollama](https://ollama.com/) running locally
- Suricata logs in `eve.json` format
- wip - some other things ;-;


### Project Structure

| File/Folder         | Purpose                                      |
|---------------------|----------------------------------------------|
| `analyze_traffic.py`| Main CLI tool for log analysis               |
| `run_analyzer.sh`   | Shell wrapper for easy execution             |
| `config.yaml`       | Config file for model and API settings     |
| `tests/`            | Test logs and (future) test scripts          |


## ❓ Need help?

- wip - Check the [FAQ](#)
- Or [open an issue](https://github.com/yourname/llm-network-analyzer/issues)
