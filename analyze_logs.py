#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CLI-скрипт для анализа логов с использованием локальной LLM.
Разработан без внешних зависимостей для простой сборки в EXE с помощью PyInstaller.
"""

import os
import sys
import json
import argparse
import logging
import urllib.request
import urllib.error
import socket

# Имя конфигурационного файла по умолчанию
CONFIG_FILENAME = "config.json"

# Стандартные настройки по умолчанию
DEFAULT_CONFIG = {
    "api_url": "http://localhost:8080/v1/chat/completions",
    "model": "local-model",
    "limit": 400,
    "variant": "1",
    "timeout": 120,
    "temperature": 0.0,
    "system_instructions": (
        "Ты системный аналитик. Проанализируй логи внутри тега <data>.\n"
        "Найди: ошибки, критические предупреждения, аномальные паттерны.\n"
        "Верни ТОЛЬКО JSON массив объектов: "
        '[{"line": номер_строки, "severity": "ERROR|WARN|INFO", "summary": "краткое описание"}]\n'
        "Не выдумывай строки. Если данных нет, верни []."
    ),
    "welcome_message": (
        "========================================================================\n"
        "Добро пожаловать в CLI-утилиту анализа логов через локальную LLM!\n"
        "========================================================================\n\n"
        "Данная утилита считывает лог-файл порциями (чанками), упаковывает их в "
        "XML-подобные теги и отправляет в API локальной модели.\n\n"
        "СТРУКТУРА ЗАПРОСА К LLM:\n"
        "1. Блок <instructions> — указывает роль модели, задачу и строгие правила вывода JSON.\n"
        "2. Блок <data> — содержит исключительно сырые строки логов для анализа.\n\n"
        "ПРИМЕР ВЫХОДНОГО ШАБЛОНА ЗАПРОСА:\n"
        "<instructions>\n"
        "Ты системный аналитик. Проанализируй логи внутри тега <data>.\n"
        "Найди: ошибки, критические предупреждения, аномальные паттерны.\n"
        "Верни ТОЛЬКО JSON массив объектов: "
        '[{"line": номер_строки, "severity": "ERROR|WARN|INFO", "summary": "краткое описание"}]\n'
        "Не выдумывай строки. Если данных нет, верни [].\n"
        "</instructions>\n\n"
        "<data>\n"
        "2026-05-21 10:00:01 [INFO] Service started on port 8080\n"
        "2026-05-21 10:00:05 [ERROR] Connection refused: postgres@10.10.10.10:5432\n"
        "2026-05-21 10:00:06 [WARN] Retry 1/3 failed. Timeout 30s\n"
        "</data>\n\n"
        "------------------------------------------------------------------------\n"
        "УСЛОВИЯ ЗАПУСКА:\n"
        "Обязательно укажите путь к файлу логов через аргумент -f или --file.\n"
        "Все параметры могут быть настроены в файле config.json.\n\n"
        "Пример запуска:\n"
        "  python analyze_logs.py -f app.log\n"
        "  (или log_analyzer.exe -f app.log)\n"
        "========================================================================"
    )
}


def get_base_dir():
    """
    Возвращает директорию запуска скрипта или скомпилированного .exe файла.
    Используется для поиска config.json в той же папке.
    """
    if getattr(sys, 'frozen', False):
        # Запуск в скомпилированном виде (PyInstaller)
        return os.path.dirname(sys.executable)
    else:
        # Запуск в виде обычного .py скрипта
        return os.path.dirname(os.path.abspath(__file__))


def load_or_create_config():
    """
    Загружает файл настроек config.json. Если его не существует,
    создает новый с настройками по умолчанию.
    """
    base_dir = get_base_dir()
    config_path = os.path.join(base_dir, CONFIG_FILENAME)

    if not os.path.exists(config_path):
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(DEFAULT_CONFIG, f, indent=2, ensure_ascii=False)
            logging.info(f"Создан новый файл настроек по умолчанию: {config_path}")
        except Exception as e:
            logging.error(f"Не удалось записать конфигурационный файл: {e}")
        return DEFAULT_CONFIG

    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
            # Дозаполняем отсутствующие ключи дефолтными значениями
            updated = False
            for k, v in DEFAULT_CONFIG.items():
                if k not in config:
                    config[k] = v
                    updated = True
            if updated:
                with open(config_path, 'w', encoding='utf-8') as wf:
                    json.dump(config, wf, indent=2, ensure_ascii=False)
            return config
    except Exception as e:
        logging.error(f"Ошибка при чтении {CONFIG_FILENAME}, используются настройки по умолчанию. Ошибка: {e}")
        return DEFAULT_CONFIG


def read_log_chunks(file_path, chunk_size):
    """
    Память-эффективный генератор для построчного чтения больших файлов.
    Возвращает чанки в виде списка строк без изменения их исходного формата.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Файл логов не найден: {file_path}")

    chunk = []
    # Используем errors='replace' для предотвращения падений при битых кодировках в логах
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            chunk.append(line)
            if len(chunk) == chunk_size:
                yield chunk
                chunk = []
        if chunk:
            yield chunk


def format_payload(instructions, chunk_lines, variant):
    """
    Упаковывает инструкции и строки логов в зависимости от флага --variant.
    Не модифицирует сами строки логов (не добавляет префиксы).
    """
    raw_logs = "".join(chunk_lines)

    if variant == "1":
        # Вариант 1 (API-Native Roles)
        system_content = f"<instructions>\n{instructions}\n</instructions>"
        user_content = f"<data>\n{raw_logs}</data>"
        return [
            {"role": "system", "content": system_content},
            {"role": "user", "content": user_content}
        ]
    else:
        # Вариант 2 (Explicit XML inside User role)
        user_content = (
            f"<SystemPrompt>\n<instructions>\n{instructions}\n</instructions>\n</SystemPrompt>\n"
            f"<UserPrompt>\n<data>\n{raw_logs}</data>\n</UserPrompt>"
        )
        return [
            {"role": "user", "content": user_content}
        ]


def send_request(api_url, model, messages, temperature, timeout):
    """
    Отправляет POST-запрос в OpenAI-совместимое API локальной LLM
    с использованием встроенной библиотеки urllib.request.
    """
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature
    }
    
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        api_url,
        data=data,
        headers={"Content-Type": "application/json"}
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            resp_data = response.read().decode('utf-8')
            return json.loads(resp_data)
    except urllib.error.HTTPError as e:
        try:
            error_body = e.read().decode('utf-8')
            logging.error(f"Ошибка API (HTTP {e.code}): {e.reason}. Ответ: {error_body}")
        except Exception:
            logging.error(f"Ошибка API (HTTP {e.code}): {e.reason}")
        raise
    except urllib.error.URLError as e:
        logging.error(f"Ошибка подключения к сети API: {e.reason}")
        raise
    except socket.timeout:
        logging.error(f"Таймаут запроса к API после {timeout} сек.")
        raise


def clean_and_parse_json(response_content):
    """
    Очищает ответ модели от markdown-разметки (например ```json ... ```)
    и извлекает валидный JSON массив.
    """
    text = response_content.strip()

    # Удаляем markdown-блоки
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 2 and lines[0].startswith("```"):
            lines = lines[1:]
        if len(lines) >= 1 and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Пытаемся найти границы массива [ ... ]
        start_idx = text.find('[')
        end_idx = text.rfind(']')
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            json_candidate = text[start_idx:end_idx + 1]
            try:
                return json.loads(json_candidate)
            except json.JSONDecodeError:
                pass
        raise ValueError(f"Не удалось распарсить ответ модели как JSON-массив. Сырой текст: {response_content}")


def main():
    # Настраиваем логирование в stderr, чтобы stdout оставался чистым для вывода JSON
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        stream=sys.stderr
    )

    # Если скрипт запущен без аргументов
    if len(sys.argv) == 1:
        config = load_or_create_config()
        print(config.get("welcome_message", DEFAULT_CONFIG["welcome_message"]), file=sys.stderr)
        
        # Создаем минимальный парсер просто для вывода красивого --help
        parser = argparse.ArgumentParser(
            description="Анализатор логов через локальную LLM.",
            add_help=True
        )
        parser.add_argument("-f", "--file", required=True, help="Путь к файлу логов")
        parser.print_help(sys.stderr)
        sys.exit(0)

    # Загружаем конфигурацию
    config = load_or_create_config()

    # Описываем CLI аргументы
    parser = argparse.ArgumentParser(
        description="CLI-скрипт для отправки логов на анализ в локальную LLM."
    )
    parser.add_argument(
        "-f", "--file",
        required=True,
        help="Путь к файлу логов для анализа (обязательный)."
    )
    parser.add_argument(
        "-u", "--api-url",
        default=config.get("api_url"),
        help=f"URL API модели (по умолчанию из config.json: {config.get('api_url')})"
    )
    parser.add_argument(
        "-l", "--limit",
        type=int,
        default=config.get("limit"),
        help=f"Размер чанка в строках (по умолчанию из config.json: {config.get('limit')})"
    )
    parser.add_argument(
        "-v", "--variant",
        choices=["1", "2"],
        default=config.get("variant"),
        help=f"Вариант упаковки XML (по умолчанию из config.json: {config.get('variant')})"
    )
    parser.add_argument(
        "-m", "--model",
        default=config.get("model"),
        help=f"Название модели в API (по умолчанию из config.json: {config.get('model')})"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=config.get("timeout"),
        help=f"Таймаут запроса к API в секундах (по умолчанию из config.json: {config.get('timeout')})"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Режим тестирования шаблона: выводит сформированный XML-запрос для первого чанка логов без отправки в API."
    )
    parser.add_argument(
        "-d", "--verbose",
        action="store_true",
        help="Включить подробный вывод отладочных логов (DEBUG)."
    )

    args = parser.parse_args()

    # Меняем уровень логирования при необходимости
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logging.info("Инициализация анализа логов...")
    logging.info(f"Параметры работы: API={args.api_url}, Модель={args.model}, Чанк={args.limit} строк, Вариант={args.variant}")

    # Чтение и отправка данных
    all_findings = []
    chunk_index = 0
    failed_chunks = 0

    try:
        chunks_generator = read_log_chunks(args.file, args.limit)
    except FileNotFoundError as e:
        logging.error(str(e))
        sys.exit(1)

    for chunk_lines in chunks_generator:
        chunk_index += 1
        logging.info(f"Обработка чанка #{chunk_index} ({len(chunk_lines)} строк)...")

        # Формируем сообщения согласно выбранному варианту разметки
        messages = format_payload(
            instructions=config.get("system_instructions", DEFAULT_CONFIG["system_instructions"]),
            chunk_lines=chunk_lines,
            variant=args.variant
        )

        # Режим тестирования шаблона (--dry-run)
        if args.dry_run:
            logging.info("=== РЕЖИМ DRY-RUN (ПЕЧАТЬ СФОРМИРОВАННОГО ШАБЛОНА ЗАПРОСА) ===")
            print(json.dumps(messages, indent=2, ensure_ascii=False))
            logging.info("Режим dry-run завершен. Дальнейшая обработка остановлена.")
            sys.exit(0)

        # Отправка запроса в API
        try:
            logging.debug(f"Отправка запроса для чанка #{chunk_index}...")
            response = send_request(
                api_url=args.api_url,
                model=args.model,
                messages=messages,
                temperature=config.get("temperature", 0.0),
                timeout=args.timeout
            )

            # Извлечение текста ответа
            try:
                response_content = response['choices'][0]['message']['content']
            except (KeyError, IndexError, TypeError) as e:
                logging.error(f"Некорректная структура ответа от API на чанке #{chunk_index}: {e}")
                logging.debug(f"Raw API response: {response}")
                failed_chunks += 1
                continue

            # Парсинг JSON
            try:
                parsed_findings = clean_and_parse_json(response_content)
                if isinstance(parsed_findings, list):
                    all_findings.extend(parsed_findings)
                    logging.info(f"Чанк #{chunk_index} успешно обработан. Найдено инцидентов: {len(parsed_findings)}")
                else:
                    logging.error(f"LLM вернула JSON, но это не массив на чанке #{chunk_index}. Ответ: {response_content}")
                    failed_chunks += 1
            except Exception as e:
                logging.error(f"Ошибка парсинга ответа LLM на чанке #{chunk_index}: {e}")
                failed_chunks += 1

        except Exception as e:
            logging.error(f"Не удалось выполнить запрос для чанка #{chunk_index}: {e}")
            failed_chunks += 1

    # Завершение анализа
    logging.info("Анализ всех чанков завершен.")
    logging.info(f"Всего обработано чанков: {chunk_index}")
    if failed_chunks > 0:
        logging.warning(f"Количество чанков, завершившихся с ошибкой: {failed_chunks}")

    # Вывод результатов в красивом отформатированном JSON (pretty print) в stdout
    # Благодаря этому вывод можно перенаправлять в файл или другие утилиты (например, analyze_logs.exe -f app.log > results.json)
    print(json.dumps(all_findings, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("\nПрограмма прервана пользователем.")
        sys.exit(130)
