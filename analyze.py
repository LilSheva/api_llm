import os
import sys
import json
import argparse
import logging
import urllib.request
import urllib.error
import socket
import time
import re

CONFIG_FILE = "config.json"
DEFAULT_CONFIG = {
    "api_url": "http://localhost:8080/v1/chat/completions",
    "model": "Meta-Llama-3.1-8B-Instruct-Q6_K.gguf",
    "limit": 400,
    "timeout": 120,
    "temperature": 0.0,
    "offset": False,
    "retries": 0,
    "sanitize": False,
    "verbose": False,
    "system_instructions": (
        "Ты системный аналитик. Проанализируй логи внутри тега <data>.\n"
        "Найди: ошибки, критические предупреждения, аномальные паттерны.\n"
        "Верни ТОЛЬКО JSON массив объектов: [{\"line\": номер_строки, \"severity\": \"ERROR|WARN|INFO\", \"summary\": \"краткое описание\"}]\n"
        "Не выдумывай строки. Если данных нет, верни []."
    )
}

def configure_logging(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s [%(levelname)s] %(message)s', stream=sys.stderr)

def load_config():
    base_dir = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(base_dir, CONFIG_FILE)
    
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return {**DEFAULT_CONFIG, **json.load(f)}
    except FileNotFoundError:
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(DEFAULT_CONFIG, f, indent=2, ensure_ascii=False)
        except OSError as e:
            logging.warning("Не удалось создать файл настроек по умолчанию: %s", e)
        return DEFAULT_CONFIG
    except json.JSONDecodeError as e:
        logging.error("Файл настроек config.json поврежден: %s. Используются параметры по умолчанию.", e)
        return DEFAULT_CONFIG

def log_chunks(file_path, size):
    chunk = []
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            chunk.append(line)
            if len(chunk) == size:
                yield "".join(chunk), len(chunk)
                chunk = []
        if chunk:
            yield "".join(chunk), len(chunk)

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
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        result = json.loads(resp.read().decode('utf-8'))
        return result['choices'][0]['message']['content']

def query_llm_with_retry(api_url, model, instructions, logs, temperature, timeout, retries=0):
    attempts = max(1, retries + 1)
    for attempt in range(attempts):
        try:
            return query_llm(api_url, model, instructions, logs, temperature, timeout)
        except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, TimeoutError) as e:
            if attempt == attempts - 1:
                raise
            wait = 2 ** attempt
            logging.warning(
                "Сбой подключения к API. Повторная попытка %d/%d через %d сек... Ошибка: %s",
                attempt + 1, retries, wait, e
            )
            time.sleep(wait)

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
        pass
    
    match = re.search(r'\[\s*\{.*\}\s*\]', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    raise ValueError(f"Не удалось извлечь валидный JSON-массив из ответа: {text[:200]}...")

def main():
    config = load_config()
    
    parser = argparse.ArgumentParser(description="Анализатор логов через локальную LLM.")
    parser.add_argument("-f", "--file", required=True, help="Путь к файлу логов.")
    parser.add_argument("-u", "--api-url", default=config["api_url"], help="URL-адрес LLM API.")
    parser.add_argument("-l", "--limit", type=int, default=config["limit"], help="Строк лога в одном чанке.")
    parser.add_argument("-m", "--model", default=config["model"], help="Имя целевой модели.")
    parser.add_argument("-t", "--timeout", type=int, default=config["timeout"], help="Таймаут запроса API в секундах.")
    parser.add_argument("--temperature", type=float, default=config["temperature"], help="Температура генерации.")
    parser.add_argument("-o", "--offset", action="store_true", default=None, help="Корректировать номера строк относительно всего файла.")
    parser.add_argument("-r", "--retries", type=int, default=None, help="Количество повторных попыток при сбоях API (по умолчанию 0).")
    parser.add_argument("--sanitize", action="store_true", default=None, help="Экранировать XML-теги внутри логов для защиты от Prompt Injection.")
    parser.add_argument("-d", "--verbose", action="store_true", default=None, help="Включить подробное логирование отладки.")
    args = parser.parse_args()

    # Слияние флагов аргументов CLI с конфигурацией config.json
    offset_enabled = args.offset if args.offset is not None else config.get("offset", False)
    retries_count = args.retries if args.retries is not None else config.get("retries", 0)
    sanitize_enabled = args.sanitize if args.sanitize is not None else config.get("sanitize", False)
    verbose_enabled = args.verbose if args.verbose is not None else config.get("verbose", False)

    configure_logging(verbose_enabled)

    if not os.path.isfile(args.file):
        logging.error("Файл логов не найден: %s", args.file)
        sys.exit(1)

    try:
        with open(args.file, 'r', encoding='utf-8', errors='replace') as f:
            total_lines = sum(1 for _ in f)
        total_chunks = max(1, (total_lines + args.limit - 1) // args.limit)
    except Exception as e:
        logging.warning("Не удалось предварительно подсчитать строки: %s. Прогресс-бар будет приблизительным.", e)
        total_chunks = 1

    findings = []
    global_line_offset = 1
    start_time = time.time()

    for idx, (chunk, chunk_size) in enumerate(log_chunks(args.file, args.limit), 1):
        if sanitize_enabled:
            chunk = chunk.replace("</data>", "<\\/data>")

        raw_response = None
        try:
            raw_response = query_llm_with_retry(
                api_url=args.api_url,
                model=args.model,
                instructions=config["system_instructions"],
                logs=chunk,
                temperature=args.temperature,
                timeout=args.timeout,
                retries=retries_count
            )
        except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, TimeoutError) as e:
            logging.error("Не удалось получить ответ для чанка №%d после всех попыток: %s", idx, e)
        except Exception as e:
            logging.error("Критическая ошибка при обработке чанка №%d: %s", idx, e)

        if raw_response:
            try:
                parsed = clean_json(raw_response)
                if isinstance(parsed, list):
                    if offset_enabled:
                        for item in parsed:
                            if isinstance(item, dict) and "line" in item:
                                try:
                                    val = item["line"]
                                    if isinstance(val, (int, float)):
                                        item["line"] = int(val) + global_line_offset - 1
                                    elif isinstance(val, str) and val.isdigit():
                                        item["line"] = int(val) + global_line_offset - 1
                                except Exception:
                                    pass
                    findings.extend(parsed)
                else:
                    logging.warning("Чанк №%d: ожидался JSON-массив, получен некорректный тип данных.", idx)
            except Exception as e:
                logging.error("Ошибка парсинга ответа для чанка №%d: %s", idx, e)

        global_line_offset += chunk_size

        elapsed = time.time() - start_time
        avg_time = elapsed / idx
        remaining_chunks = total_chunks - idx
        eta = avg_time * remaining_chunks
        
        percent = int((idx / total_chunks) * 100)
        bar = "=" * (percent // 10) + "-" * (10 - (percent // 10))
        eta_str = f"{eta:.0f}с" if eta > 0 else "--"
        sys.stderr.write(f"\r[{bar}] {percent}% | Чанк {idx}/{total_chunks} | Осталось: ~{eta_str}")
        sys.stderr.flush()

    sys.stderr.write("\n")
    sys.stderr.flush()

    print(json.dumps(findings, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
