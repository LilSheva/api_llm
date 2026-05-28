import os
import sys
import json
import argparse
import logging
import urllib.request
import urllib.error

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', stream=sys.stderr)

CONFIG_FILE = "config.json"
DEFAULT_CONFIG = {
    "api_url": "http://localhost:8080/v1/chat/completions",
    "model": "Meta-Llama-3.1-8B-Instruct-Q6_K.gguf",
    "limit": 400,
    "timeout": 120,
    "temperature": 0.0,
    "system_instructions": (
        "Ты системный аналитик. Проанализируй логи внутри тега <data>.\n"
        "Найди: ошибки, критические предупреждения, аномальные паттерны.\n"
        "Верни ТОЛЬКО JSON массив объектов: [{\"line\": номер_строки, \"severity\": \"ERROR|WARN|INFO\", \"summary\": \"краткое описание\"}]\n"
        "Не выдумывай строки. Если данных нет, верни []."
    )
}

def load_config():
    base_dir = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(base_dir, CONFIG_FILE)
    
    if not os.path.exists(path):
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(DEFAULT_CONFIG, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logging.warning(f"Failed to create default config: {e}")
        return DEFAULT_CONFIG

    try:
        with open(path, 'r', encoding='utf-8') as f:
            return {**DEFAULT_CONFIG, **json.load(f)}
    except Exception as e:
        logging.error(f"Failed to read config, using defaults: {e}")
        return DEFAULT_CONFIG

def log_chunks(file_path, size):
    chunk = []
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            chunk.append(line)
            if len(chunk) == size:
                yield "".join(chunk)
                chunk = []
        if chunk:
            yield "".join(chunk)

def query_llm(api_url, model, instructions, logs, temperature, timeout):
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": f"<instructions>\n{instructions}\n</instructions>"},
            {"role": "user", "content": f"<data>\n{logs}</data>"}
        ],
        "temperature": temperature
    }
    req = urllib.request.Request(
        api_url,
        data=json.dumps(payload).encode('utf-8'),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result = json.loads(resp.read().decode('utf-8'))
            return result['choices'][0]['message']['content']
    except Exception as e:
        logging.error(f"API request failed: {e}")
        return None

def clean_json(text):
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find('['), text.rfind(']')
        if -1 < start < end:
            try:
                return json.loads(text[start:end+1])
            except json.JSONDecodeError:
                pass
        raise ValueError(f"Invalid JSON response: {text[:200]}...")

def main():
    config = load_config()
    parser = argparse.ArgumentParser(description="Memory-efficient log analyzer using a local LLM.")
    parser.add_argument("-f", "--file", required=True, help="Path to the log file.")
    parser.add_argument("-u", "--api-url", default=config["api_url"], help="LLM API endpoint.")
    parser.add_argument("-l", "--limit", type=int, default=config["limit"], help="Lines per chunk.")
    parser.add_argument("-m", "--model", default=config["model"], help="Target model identifier.")
    parser.add_argument("-t", "--timeout", type=int, default=config["timeout"], help="Request timeout (seconds).")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        logging.error(f"File not found: {args.file}")
        sys.exit(1)

    findings = []
    for idx, chunk in enumerate(log_chunks(args.file, args.limit), 1):
        logging.info(f"Processing chunk #{idx}...")
        raw_response = query_llm(args.api_url, args.model, config["system_instructions"], chunk, config["temperature"], args.timeout)
        if not raw_response:
            continue
        try:
            parsed = clean_json(raw_response)
            if isinstance(parsed, list):
                findings.extend(parsed)
                logging.info(f"Chunk #{idx} processed. Found {len(parsed)} issues.")
            else:
                logging.warning(f"Unexpected JSON format in response for chunk #{idx}.")
        except Exception as e:
            logging.error(f"Failed to parse chunk #{idx}: {e}")

    print(json.dumps(findings, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
