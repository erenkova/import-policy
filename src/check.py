import sys
import os  
import json
import subprocess
import re
import argparse
import glob  
from pathlib import Path
from datetime import datetime
import platform
import tempfile
import shutil
import uuid
import time
import pwd
import grp

# БЛОК 0

def extract_file_paths_from_rego(policy_path):
    """
    Извлекает пути к файлам из Rego политики.
    Ищет паттерны вида: input.files["/path/to/file"].permissions
    """
    policy_file = Path(policy_path)
    if not policy_file.exists():
        return []
    
    try:
        content = policy_file.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        content = policy_file.read_text(encoding='cp1251', errors='ignore')
    
    pattern = r'input\.files\["([^"]+)"\]'
    matches = re.findall(pattern, content)
    
    unique_paths = list(set(matches))
    
    
    filtered_paths = unique_paths
    
    return filtered_paths

# БЛОК 0.5

def extract_expected_config_keys_from_rego(policy_path):
    """
    Извлекает ожидаемые ключи конфигурации из Rego политики.
    Ищет паттерны вида: input.config.key_name ТОЛЬКО в блоках deny[msg]
    Возвращает словарь {config_key: [policy_code1, policy_code2, ...]}
    """
    policy_file = Path(policy_path)
    if not policy_file.exists():
        return {}
    
    try:
        content = policy_file.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        content = policy_file.read_text(encoding='cp1251', errors='ignore')
    
    
    deny_blocks = re.findall(r'deny\[msg\]\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}', content, re.DOTALL)
    
    all_keys = {}  
    
    for block in deny_blocks:
        # Извлекаем policy_code из блока
        policy_code = "UNKNOWN"
        code_match = re.search(r'\[([A-Z]{2,}_\d[\w_]*)\]', block, re.IGNORECASE)
        if code_match:
            policy_code = code_match.group(1)
        
        # Ищем input.config.key_name
        pattern = r'input\.config\.([a-zA-Z_][a-zA-Z0-9_]*)'
        matches = re.findall(pattern, block)
        for key in matches:
            if key not in ['_text', '_attrib', '_raw_content']:
                key_lower = key.lower()
                if key_lower not in all_keys:
                    all_keys[key_lower] = []
                if policy_code not in all_keys[key_lower]:
                    all_keys[key_lower].append(policy_code)
        
        # Ищем input.config["key_name"]
        pattern2 = r'input\.config\["([^"]+)"\]'
        matches2 = re.findall(pattern2, block)
        for key in matches2:
            if key not in ['_text', '_attrib', '_raw_content']:
                key_lower = key.lower()
                if key_lower not in all_keys:
                    all_keys[key_lower] = []
                if policy_code not in all_keys[key_lower]:
                    all_keys[key_lower].append(policy_code)
        
        # Ищем input.config['key_name']
        pattern3 = r"input\.config\['([^']+)'\]"
        matches3 = re.findall(pattern3, block)
        for key in matches3:
            if key not in ['_text', '_attrib', '_raw_content']:
                key_lower = key.lower()
                if key_lower not in all_keys:
                    all_keys[key_lower] = []
                if policy_code not in all_keys[key_lower]:
                    all_keys[key_lower].append(policy_code)
    
    return all_keys

# БЛОК 0.6 
def extract_expected_values_from_rego(policy_path):
    """
    Извлекает ожидаемые значения для параметров из Rego политики.
    Возвращает словарь {config_key: {policy_code: expected_value}}
    """
    policy_file = Path(policy_path)
    if not policy_file.exists():
        return {}
    
    try:
        content = policy_file.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        content = policy_file.read_text(encoding='cp1251', errors='ignore')
    
    expected_values = {} 
    
    # Разбиваем на блоки deny[msg]
    deny_blocks = re.findall(r'deny\[msg\]\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}', content, re.DOTALL)
    
    for block in deny_blocks:
        # Извлекаем policy_code
        policy_code = "UNKNOWN"
        code_match = re.search(r'\[([A-Z]{2,}_\d[\w_]*)\]', block, re.IGNORECASE)
        if code_match:
            policy_code = code_match.group(1)
        
        # Ищем input.config.key
        key_match = re.search(r'input\.config\.([a-zA-Z_][a-zA-Z0-9_]*)', block)
        if not key_match:
            continue
        
        key = key_match.group(1).lower()
        
        
        if key in ['_text', '_attrib', '_raw_content']:
            continue
        
        expected_value = None
        
        # Вариант 1: lower(input.config.key) != "value" или input.config.key != "value"
        value_match = re.search(r'lower\(input\.config\.[a-zA-Z_][a-zA-Z0-9_]*\)\s*!=\s*"([^"]+)"', block)
        if not value_match:
            value_match = re.search(r'input\.config\.[a-zA-Z_][a-zA-Z0-9_]*\s*!=\s*"([^"]+)"', block)
        if not value_match:
            value_match = re.search(r'input\.config\.[a-zA-Z_][a-zA-Z0-9_]*\s*!=\s*(\d+(?:\.\d+)?)', block)
        
        if value_match:
            expected_value = value_match.group(1)
        
        # Вариант 2: not contains(lower(input.config.key), "value")
        if not expected_value:
            contains_match = re.search(r'not\s+contains\([^,]+,\s*"([^"]+)"\)', block)
            if contains_match:
                expected_value = f"содержит '{contains_match.group(1)}'"
        
        # Вариант 3: not any_allowed_*(input.config.key) - список значений
        if not expected_value:
            allowed_func_match = re.search(r'not\s+any_allowed_\w+\(input\.config\.[a-zA-Z_][a-zA-Z0-9_]*\)', block)
            if allowed_func_match:
                func_name_match = re.search(r'any_allowed_(\w+)\(', content)
                if func_name_match:
                    allowed_pattern = rf'any_allowed_{func_name_match.group(1)}\(value\)\s*\{{[^}}]*allowed\s*:=\s*\[([^\]]+)\]'
                    allowed_match = re.search(allowed_pattern, content, re.DOTALL)
                    if allowed_match:
                        values = allowed_match.group(1).replace('"', '').replace("'", '').strip()
                        expected_value = f"одно из: [{values}]"
        
        if expected_value:
            if key not in expected_values:
                expected_values[key] = {}
            expected_values[key][policy_code] = expected_value
    
    return expected_values



# БЛОК 0.7 

def count_deny_rules_in_rego(policy_path):
    """
    Подсчитывает количество правил deny[msg] в файле Rego.
    Возвращает общее количество политик безопасности.
    """
    policy_file = Path(policy_path)
    if not policy_file.exists():
        return 0
    
    try:
        content = policy_file.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        content = policy_file.read_text(encoding='cp1251', errors='ignore')
    
    # Удаляем комментарии (строки, начинающиеся с #)
    lines = content.split('\n')
    cleaned_lines = []
    for line in lines:
        # Убираем комментарии, но только если # не внутри строки
        stripped = line.strip()
        if not stripped.startswith('#'):
            cleaned_lines.append(line)
    
    cleaned_content = '\n'.join(cleaned_lines)
    
    # Ищем именно объявления deny[msg] {
    
    pattern = r'deny\[msg\]\s*\{'
    matches = re.findall(pattern, cleaned_content)
    
    count = len(matches)
    
    
    
    return count

# БЛОК 1

def get_file_permissions_linux(file_pattern):
    """
    Получает права на файл в Linux (локально).
    Возвращает строку с правами (например, "640") или None.
    """
    try:
        if '*' not in file_pattern:
            file_path = Path(file_pattern)
            if file_path.exists():
                mode = os.stat(file_path).st_mode
                permissions = oct(mode)[-3:]
                return permissions  
        else:
            files = glob.glob(file_pattern)
            if files:
                mode = os.stat(files[0]).st_mode
                permissions = oct(mode)[-3:]
                return permissions  
    except Exception as e:
        print(f"    Не удалось получить права на файл {file_pattern}: {e}")
    
    return None

def get_file_owner_linux(file_pattern):
    """
    Получает владельца файла в Linux (локально).
    Возвращает имя владельца (например, "root") или None.
    """
    try:
        if '*' not in file_pattern:
            file_path = Path(file_pattern)
            if file_path.exists():
                stat_info = os.stat(file_path)
                uid = stat_info.st_uid
                try:
                    owner = pwd.getpwuid(uid).pw_name
                except KeyError:
                    owner = str(uid)
                return owner
        else:
            files = glob.glob(file_pattern)
            if files:
                stat_info = os.stat(files[0])
                uid = stat_info.st_uid
                try:
                    owner = pwd.getpwuid(uid).pw_name
                except KeyError:
                    owner = str(uid)
                return owner
    except Exception as e:
        print(f"    Не удалось получить владельца файла {file_pattern}: {e}")
    
    return None

# БЛОК 2
def check_actual_file_permissions(files_to_check_list=None, docker_id=None, temp_image_container_id=None):
    """
    Проверяет права доступа к файлам.
    Если указан docker_id или temp_image_container_id, проверка выполняется внутри контейнера.
    Возвращает кортеж: (словарь с правами и владельцами, список непроверенных прав, список непроверенных владельцев)
    """
    files_dict = {}
    unchecked_permissions = []
    unchecked_owners = []
    
    if not files_to_check_list:
        print("   Список файлов для проверки прав не предоставлен.")
        return files_dict, unchecked_permissions, unchecked_owners
    
    print("   Проверка прав доступа к файлам...")
    
    # Определяем ID контейнера для проверки (либо запущенный, либо временный из образа)
    target_container_id = docker_id or temp_image_container_id

    if target_container_id:
        if not is_docker_available():
            print("   ERROR: Docker не найден, но указан идентификатор контейнера/образа.")
            return files_dict, files_to_check_list, files_to_check_list
            
        for file_pattern in files_to_check_list:
           
            if '*' in file_pattern:
                print(f"     {file_pattern}: Глоб-паттерн, требуется дополнительная обработка")
                unchecked_permissions.append(file_pattern)
                unchecked_owners.append(file_pattern)
                continue
            
            perms = get_file_permissions_docker(target_container_id, file_pattern)
            owner = get_file_owner_docker(target_container_id, file_pattern)
            
            if perms is not None or owner is not None:
                files_dict[file_pattern] = {}
                if perms:
                    files_dict[file_pattern]["permissions"] = perms
                else:
                    unchecked_permissions.append(file_pattern)
                if owner:
                    files_dict[file_pattern]["owner"] = owner
                else:
                    unchecked_owners.append(file_pattern)
                    
                display_id = target_container_id[:12]
                print(f"     [{display_id}] {file_pattern}: права {perms}, владелец {owner}")
            else:
                unchecked_permissions.append(file_pattern)
                unchecked_owners.append(file_pattern)
                display_id = target_container_id[:12]
                print(f"     [{display_id}] {file_pattern}: файл не найден или недоступен внутри контейнера")
        return files_dict, unchecked_permissions, unchecked_owners

    
    if platform.system() != 'Linux':
        print("   Проверка прав на файлы пропущена (не Linux)")
        return files_dict, files_to_check_list, files_to_check_list
    
    for file_pattern in files_to_check_list:
        
        if '*' in file_pattern:
            files = glob.glob(file_pattern)
            if files:
                for file_path in files:
                    perms = get_file_permissions_linux(file_path)
                    owner = get_file_owner_linux(file_path)
                    
                    if perms is not None or owner is not None:
                        files_dict[file_path] = {}
                        if perms:
                            files_dict[file_path]["permissions"] = perms
                        else:
                            unchecked_permissions.append(file_path)
                        if owner:
                            files_dict[file_path]["owner"] = owner
                        else:
                            unchecked_owners.append(file_path)
                        print(f"     {file_path}: права {perms}, владелец {owner}")
                    else:
                        unchecked_permissions.append(file_path)
                        unchecked_owners.append(file_path)
            else:
                unchecked_permissions.append(file_pattern)
                unchecked_owners.append(file_pattern)
                print(f"     {file_pattern}: файлы не найдены")
            continue
            
        perms = get_file_permissions_linux(file_pattern)
        owner = get_file_owner_linux(file_pattern)
        
        if perms is not None or owner is not None:
            files_dict[file_pattern] = {}
            if perms:
                files_dict[file_pattern]["permissions"] = perms
            else:
                unchecked_permissions.append(file_pattern)
            if owner:
                files_dict[file_pattern]["owner"] = owner
            else:
                unchecked_owners.append(file_pattern)
            print(f"     {file_pattern}: права {perms}, владелец {owner}")
        else:
            unchecked_permissions.append(file_pattern)
            unchecked_owners.append(file_pattern)
            if '*' in file_pattern:
                print(f"     {file_pattern}: файлы не найдены или недоступны")
            else:
                print(f"     {file_pattern}: файл не найден или недоступен")
    
    return files_dict, unchecked_permissions, unchecked_owners

# ФУНКЦИИ ДЛЯ РАБОТЫ С DOCKER (БЛОК 2.5) ---

def is_docker_available():
    """Проверяет наличие утилиты docker в PATH."""
    try:
        result = subprocess.run(["docker", "--version"], capture_output=True, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False

def verify_container_running(container_id):
    """Проверяет, запущен ли контейнер с таким ID или именем."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container_id],
            capture_output=True, text=True
        )
        if result.returncode == 0 and result.stdout.strip() == "true":
            return True
        elif result.returncode == 0:
            print(f"   ERROR: Контейнер {container_id} существует, но не запущен.")
            return False
        else:
            print(f"   ERROR: Контейнер {container_id} не найден.")
            return False
    except Exception as e:
        print(f"   ERROR: Ошибка при проверке статуса контейнера: {e}")
        return False

def create_temp_container_from_image(image_name):
    """
    Создает временный остановленный контейнер из образа.
    Возвращает ID созданного контейнера или None в случае ошибки.
    """
    print(f"   Создание временного контейнера из образа: {image_name}...")
    
    # Генерируем уникальное имя для временного контейнера
    temp_name = f"audit_temp_{uuid.uuid4().hex[:8]}"
    
    cmd = ["docker", "create", "--name", temp_name, image_name, "sleep", "infinity"]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            container_id = result.stdout.strip()
            print(f"    Временный контейнер создан: {container_id[:12]} (Имя: {temp_name})")
            return container_id, temp_name
        else:
            print(f"    ERROR: Не удалось создать контейнер из образа {image_name}")
            print(f"    STDERR: {result.stderr}")
            return None, None
    except Exception as e:
        print(f"    ERROR: Исключение при создании контейнера: {e}")
        return None, None

def remove_temp_container(container_id, container_name):
    """Удаляет временный контейнер."""
    if not container_id:
        return
        
    print(f"   Удаление временного контейнера: {container_id[:12]}...")
    try:
        # Сначала пытаемся остановить, если вдруг он запущен, затем удалить
        subprocess.run(["docker", "stop", container_id], capture_output=True, timeout=5)
        result = subprocess.run(["docker", "rm", "-f", container_id], capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"    Временный контейнер успешно удален.")
        else:
            print(f"    WARNING: Не удалось удалить контейнер полностью: {result.stderr}")
    except Exception as e:
        print(f"    WARNING: Ошибка при удалении контейнера: {e}")

def get_file_permissions_docker(container_id, file_path):
    """
    Получает права на файл внутри контейнера через docker exec (или run для остановленных).
    Возвращает строку с правами (например, "640") или None.
    """
    try:
        # Проверяем, запущен ли контейнер
        running_check = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container_id],
            capture_output=True, text=True
        )
        is_running = running_check.stdout.strip() == "true"
        
        was_stopped = False
        if not is_running:
            subprocess.run(["docker", "start", container_id], capture_output=True)
            was_stopped = True
            time.sleep(1)  
        
        cmd = ["docker", "exec", container_id, "stat", "-c", "%a", file_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if was_stopped:
            subprocess.run(["docker", "stop", container_id], capture_output=True)
        
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            return None
    except Exception as e:
        print(f"    Не удалось получить права внутри контейнера {file_path}: {e}")
        return None

def get_file_owner_docker(container_id, file_path):
    """
    Получает владельца файла внутри контейнера через docker exec.
    Возвращает имя владельца (например, "root") или None.
    """
    try:
        # Проверяем, запущен ли контейнер
        running_check = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container_id],
            capture_output=True, text=True
        )
        is_running = running_check.stdout.strip() == "true"
        
        was_stopped = False
        if not is_running:
            subprocess.run(["docker", "start", container_id], capture_output=True)
            was_stopped = True
            time.sleep(1)  
        
        # Получаем имя владельца файла
        cmd = ["docker", "exec", container_id, "stat", "-c", "%U", file_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if was_stopped:
            subprocess.run(["docker", "stop", container_id], capture_output=True)
        
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            return None
    except Exception as e:
        print(f"    Не удалось получить владельца файла внутри контейнера {file_path}: {e}")
        return None

def extract_config_from_docker(container_id, container_config_path, temp_dir):
    """
    Копирует конфигурационный файл из контейнера во временную директорию.
    Автоматически разрешает символические ссылки.
    """
    try:
        container_safe_name = re.sub(r'[^\w\-_]', '_', container_id)
        target_dir = Path(temp_dir) / container_safe_name
        target_dir.mkdir(parents=True, exist_ok=True)
        
        filename = Path(container_config_path).name
        local_path = target_dir / filename
        
        # Проверка статуса и запуск если нужно
        running_check = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container_id],
            capture_output=True, text=True
        )
        is_running = running_check.stdout.strip() == "true"
        
        was_stopped = False
        if not is_running:
            subprocess.run(["docker", "start", container_id], capture_output=True)
            was_stopped = True
            time.sleep(1)

        # --- Проверяем, является ли файл симлинком, и получаем реальный путь ---
        real_path_cmd = ["docker", "exec", container_id, "readlink", "-f", container_config_path]
        real_path_result = subprocess.run(real_path_cmd, capture_output=True, text=True)
        
        path_to_copy = container_config_path
        if real_path_result.returncode == 0 and real_path_result.stdout.strip():
            resolved_path = real_path_result.stdout.strip()
            if resolved_path != container_config_path:
                print(f"    Обнаружена символическая ссылка. Реальный путь: {resolved_path}")
                path_to_copy = resolved_path
        

        cmd = ["docker", "cp", f"{container_id}:{path_to_copy}", str(local_path)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if was_stopped:
            subprocess.run(["docker", "stop", container_id], capture_output=True)
        
        if result.returncode == 0:
            print(f"    Файл скопирован из контейнера: {path_to_copy} -> {local_path}")
            return str(local_path)
        else:
            print(f"    ERROR: Не удалось скопировать файл: {result.stderr}")
            return None
            
    except Exception as e:
        print(f"    ERROR: Ошибка при копировании файла: {e}")
        return None



def _xml_to_dict(element):
    """Вспомогательная функция для конвертации XML в словарь."""
    result = {}
    for child in element:
        child_data = _xml_to_dict(child)
        if child.tag in result:
            if not isinstance(result[child.tag], list):
                result[child.tag] = [result[child.tag]]
            result[child.tag].append(child_data)
        else:
            result[child.tag] = child_data
    if element.text and element.text.strip():
        result['_text'] = element.text.strip()
    if element.attrib:
        result['_attrib'] = element.attrib
    return result


# БЛОК 3
def parse_config_to_conftest_input(config_path, files_data=None):
    """
    Универсальный парсер.
    Поддерживает форматы: MySQL/MariaDB (.conf), Nginx/Apache (.conf), JSON, YAML.
    ИСПРАВЛЕНО: все строковые значения приводятся к нижнему регистру для регистронезависимого сравнения
    """
    config_file = Path(config_path)
    if not config_file.exists():
        raise FileNotFoundError(f"Конфигурационный файл не найден: {config_file.resolve()}")

    file_extension = config_file.suffix.lower()
    
    try:
        content = config_file.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        content = config_file.read_text(encoding='cp1251')

    conftest_input = {
        "config": {},
        "files": files_data if files_data else {},
        "metadata": {
            "filename": config_file.name,
            "filepath": str(config_file.resolve()),
            "file_type": file_extension,
            "parsed_at": datetime.now().isoformat(),
            "source": "local_host"
        }
    }

    if file_extension in ['.conf']:
        config_dict = {}
        directive_counts = {}
        
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            if not line or line.startswith('#') or line.startswith(';'):
                continue
            
            key = None
            value = None
            
            mysql_match = re.match(r'^([\w_]+)\s*=\s*(.+)$', line)
            if mysql_match:
                key = mysql_match.group(1).strip()
                value = mysql_match.group(2).strip().strip('"').strip("'")
            
            if key is None:
                nginx_match = re.match(r'^\s*([\w_]+)\s+([^;#\n]+);', line)
                if nginx_match:
                    key = nginx_match.group(1).strip()
                    value = nginx_match.group(2).strip().strip('"').strip("'")
            
            if key is None or value is None:
                continue
            
            directive_counts[key] = directive_counts.get(key, 0) + 1
            
            
            key = key.lower()
            
            if value.lower() in ['on', 'off']:
                value = value.lower()  
            elif value.lower() in ['yes', 'no']:
                value = value.lower()  
            elif value.lower() in ['true', 'false']:
                value = value.lower()  
            
            elif value.lower() == 'null':
                value = None
            else:
                try:
                    if '.' in value:
                        value = float(value)
                    else:
                        value = int(value)
                except ValueError:
                    
                    value = value.lower()
            
            if key in ['proxy_hide_header', 'proxy_set_header']:
                if key in config_dict:
                    config_dict[key] += f", {value}"
                else:
                    config_dict[key] = value
            
            elif key == 'limit_req_zone':
                rate_match = re.search(r'rate=\d+[smhd]', str(value))
                if rate_match:
                    config_dict[key] = rate_match.group(0)
                else:
                    config_dict[key] = value
            
            elif key == 'add_header':
                if key not in config_dict:
                    config_dict[key] = []
                config_dict[key].append(value)
            
            elif key in ['keepalive_timeout', 'send_timeout']:
                config_dict[key] = str(value)
            
            elif key in ['client_header_timeout', 'client_body_timeout']:
                try:
                    config_dict[key] = int(value)
                except ValueError:
                    config_dict[key] = value
            
            else:
                if key not in config_dict:
                    config_dict[key] = value
                else:
                    if not isinstance(config_dict[key], list):
                        config_dict[key] = [config_dict[key]]
                    config_dict[key].append(value)
        
        conftest_input["config"] = config_dict
    
    
    elif file_extension in ['.json']:
        conftest_input["config"] = json.loads(content)
    elif file_extension in ['.yaml', '.yml']:
        try:
            import yaml
            conftest_input["config"] = yaml.safe_load(content) or {}
        except ImportError:
            conftest_input["config"]["_raw_content"] = content
    else:
        conftest_input["config"]["_raw_content"] = content

    return conftest_input


# БЛОК 4 
def check_and_fix_rego_policy(policy_path):
    """
    Проверяет синтаксис Rego политики в среде Linux.
    """
    policy_file = Path(policy_path)
    if not policy_file.exists():
        raise FileNotFoundError(f"Файл политики не найден: {policy_file.resolve()}")
    
    try:
        content = policy_file.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        print("   WARNING: Файл политики не в UTF-8. Попытка чтения...")
        content = policy_file.read_text(errors='ignore')

    print("   Проверка синтаксиса Rego политики...")
    
    cmd_check = ["opa", "check", str(policy_file)]
    
    try:
        result = subprocess.run(
            cmd_check, 
            capture_output=True, 
            text=True, 
            check=False
        )
        
        if result.stderr:
            print(f"   [OPA Output]: {result.stderr.strip()}")

        if result.returncode != 0:
            print(f"    ERROR: Обнаружены ошибки синтаксиса в политике!")
            print(f"   Файл: {policy_file.name}")
            print("-" * 40)
            print(result.stderr)
            print("-" * 40)
            print(f"   Проверка остановлена. Исправьте ошибки в .rego файле.")
            sys.exit(1)
        else:
            print("    Синтаксис политики корректен.")
            return policy_file
            
    except FileNotFoundError:
        print("    WARNING: Утилита 'opa' не найдена в PATH.")
        print("   Предварительная проверка синтаксиса пропущена.")
        return policy_file
    except Exception as e:
        print(f"   ERROR: Неожиданная ошибка при проверке политики: {e}")
        sys.exit(1)

# БЛОК 5
def run_conftest(input_json_path, policy_path):
    """
    Запускает conftest с указанным JSON и политикой.
    """
    cmd = [
        "conftest", 
        "test", 
        str(input_json_path), 
        "--policy", str(policy_path), 
        "--output", "json"
    ]

    print(f"   Запуск команды: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            check=False,
            encoding='utf-8',
            errors='replace'
        )
        return result.stdout, result.stderr, result.returncode
    except FileNotFoundError:
        raise Exception("Conftest не найден в PATH.")


# БЛОК 8
def format_violations(conftest_results, missing_keys=None, missing_keys_policy_codes=None):
    """
    Форматирует нарушения из вывода conftest в читаемый формат.
    """
    formatted_violations = []
    
   
    if missing_keys:
        for key, expected_value in missing_keys.items():
            policy_code = "UNKNOWN"
            if missing_keys_policy_codes and key in missing_keys_policy_codes:
                policy_code = missing_keys_policy_codes[key]
            formatted_violations.append({
                "policy_code": policy_code,
                "category": "Отсутствующий параметр",
                "message": f"Параметр '{key}' отсутствует в конфигурационном файле",
                "expected": f"{expected_value}",  
                "namespace": "config_check",
                "filename": ""
            })
    
    if not conftest_results:
        return formatted_violations
    
    if isinstance(conftest_results, dict):
        results_list = [conftest_results]
    elif isinstance(conftest_results, list):
        results_list = conftest_results
    else:
        print(f"   WARNING: Неожиданный тип данных от conftest: {type(conftest_results)}")
        return formatted_violations
    
    def parse_failure_message(msg, filename='', namespace=''):
        policy_code = "UNKNOWN"
        code_match = re.search(r'\[?([A-Z]{2,}_\d[\w_]*)\]?', msg, re.IGNORECASE)
        if code_match:
            policy_code = code_match.group(1)
            msg_for_category = msg.replace(code_match.group(0), '', 1)
        else:
            msg_for_category = msg
        
        category = "Без категории"
        category_match = re.search(r'\[([^\]]+)\]', msg_for_category)
        if category_match:
            category = category_match.group(1).strip()
        
        expected = None
        expected_patterns = [
            r'(?:Ожидалось|Expected)[:\s]+([^\[\];\n]+)',
            r'(?:должно быть|must be|should be)[:\s]+([^\[\];\n]+)',
            r'(?:value|значение)[:\s]+([^\[\];\n]+)',
        ]
        for pattern in expected_patterns:
            expected_match = re.search(pattern, msg, re.IGNORECASE)
            if expected_match:
                expected = expected_match.group(1).strip()
                break
        
        return {
            "policy_code": policy_code,
            "category": category,
            "message": msg.strip(),
            "expected": expected,
            "namespace": namespace,
            "filename": filename
        }
    
    for result_item in results_list:
        if not isinstance(result_item, dict):
            continue
            
        failures = result_item.get('failures', [])
        filename = result_item.get('filename', '')
        namespace = result_item.get('namespace', '')
        
        for failure in failures:
            if not isinstance(failure, dict):
                continue
                
            msg = failure.get('msg', failure.get('message', 'Неизвестная ошибка'))
            if not msg:
                continue
            
            violation_data = parse_failure_message(msg, filename, namespace)
            formatted_violations.append(violation_data)
    
    return formatted_violations


# БЛОК 9
def save_report(report_data, output_path):
    """
    Сохраняет отчет в JSON.
    """
    try:
        output_file = Path(output_path)
        
        if output_file.exists() and output_file.is_dir():
            print(f"   ERROR: Путь вывода является директорией: {output_file.resolve()}")
            return False
        
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
            
        print(f"\n   Отчет сохранен: {output_file.resolve()}")
        return True
        
    except PermissionError:
        print(f"   ERROR: Нет прав на запись в файл: {output_file.resolve()}")
        return False
    except TypeError as e:
        print(f"   ERROR: Ошибка формата данных для JSON: {e}")
        return False
    except Exception as e:
        print(f"   ERROR: Не удалось сохранить отчет: {e}")
        return False


# БЛОК 10
def main():
    parser = argparse.ArgumentParser(
        description='Универсальная проверка конфигурационных файлов (Локально, Docker Container или Docker Image)'
    )
    parser.add_argument('-c', '--config', required=True, help='Путь к конфигурационному файлу (локальный или путь внутри контейнера/образа)')
    parser.add_argument('-p', '--policy', required=True, help='Путь к файлу политики Rego')
    parser.add_argument('-o', '--output', required=True, help='Путь к выходному JSON файлу (или директория)')
    parser.add_argument('-f', '--files', nargs='*', default=[], help='Дополнительные файлы для проверки прав')
    
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-d', '--docker-id', help='ID или имя ЗАПУЩЕННОГО контейнера')
    group.add_argument('-i', '--image', help='Имя ОБРАЗА контейнера (скрипт создаст временный контейнер)')
    
    args = parser.parse_args()
    
    
    policy_path = Path(args.policy).expanduser().resolve()
    
    # Если указан вывод в директорию, создаем имя файла автоматически
    output_arg = Path(args.output).expanduser()
    if output_arg.is_dir():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        source_suffix = ""
        if args.docker_id:
            source_suffix = f"_{args.docker_id[:12]}"
        elif args.image:
            safe_image_name = re.sub(r'[^\w\-_]', '_', args.image.split(':')[0])
            source_suffix = f"_{safe_image_name}"
            
        output_path = output_arg / f"audit_report{source_suffix}_{timestamp}.json"
    else:
        output_path = output_arg.resolve()

    config_path_str = args.config
    
    #
    is_docker_container_mode = bool(args.docker_id)
    is_docker_image_mode = bool(args.image)
    is_docker_mode = is_docker_container_mode or is_docker_image_mode
    
    temp_dir = None
    local_config_path = None
    temp_container_id = None
    temp_container_name = None

    print("=" * 70)
    print("                    UNIVERSAL AUDIT RUNNER")
    print("=" * 70)
    
    if is_docker_mode:
        source_desc = args.docker_id if is_docker_container_mode else f"Image: {args.image}"
        print(f"\n Режим: Docker ({'Container' if is_docker_container_mode else 'Image'})")
        print(f" Источник:              {source_desc}")
        print(f" Путь к конфигу (внутр):{config_path_str}")
        
        if not is_docker_available():
            print("   ERROR: Утилита 'docker' не найдена в PATH.")
            sys.exit(1)
        
        # Логика для Образа: создание временного контейнера
        if is_docker_image_mode:
            temp_container_id, temp_container_name = create_temp_container_from_image(args.image)
            if not temp_container_id:
                print("   ERROR: Не удалось создать временный контейнер из образа.")
                sys.exit(1)
            # Используем этот ID для всех дальнейших операций
            active_docker_id = temp_container_id
            print(f"   Используется временный контейнер: {active_docker_id[:12]}")
            
        else:
            # Логика для запущенного контейнера
            if not verify_container_running(args.docker_id):
                sys.exit(1)
            active_docker_id = args.docker_id

        # Создание временной директории для извлечения файлов
        temp_dir = tempfile.mkdtemp(prefix="audit_docker_")
        print(f"   Временная директория:  {temp_dir}")
        
        # Извлечение конфига
        local_config_path = extract_config_from_docker(active_docker_id, config_path_str, temp_dir)
        if not local_config_path:
            print("   ERROR: Не удалось извлечь конфигурационный файл.")
            if temp_container_id:
                remove_temp_container(temp_container_id, temp_container_name)
            if temp_dir:
                shutil.rmtree(temp_dir)
            sys.exit(1)
            
        config_path = Path(local_config_path)
        
    else:
        print(f"\n Режим: Локальная система")
        config_path = Path(config_path_str).expanduser().resolve()
        print(f" Конфигурационный файл: {config_path}")
        active_docker_id = None

    print(f" Политика:              {policy_path}")
    print(f" Результат:             {output_path}")
    print()

    print("0. Проверка синтаксиса Rego политики...")
    try:
        checked_policy_path = check_and_fix_rego_policy(policy_path)
    except Exception as e:
        print(f"   ERROR: {e}")
        if temp_container_id:
            remove_temp_container(temp_container_id, temp_container_name)
        if temp_dir: shutil.rmtree(temp_dir)
        sys.exit(1)


    print("\n0.5. Извлечение путей к файлам из политики...")
    files_from_policy = extract_file_paths_from_rego(checked_policy_path)
    print(f"    Найдено путей в политике: {len(files_from_policy)}")
    
    
    print("\n0.6. Извлечение ожидаемых параметров конфигурации из политики...")
    expected_config_keys_with_codes = extract_expected_config_keys_from_rego(checked_policy_path)
    expected_config_keys = list(expected_config_keys_with_codes.keys())
    print(f"    Найдено ожидаемых параметров: {len(expected_config_keys)}")
    
    missing_keys = {}
    missing_keys_policy_codes = {}
    if expected_config_keys:
        print(f"    Будет выполнена проверка наличия параметров после парсинга")
    
    print("\n0.7. Подсчет количества политик в файле Rego...")
    
    # Читаем файл политики для подсчета
    try:
        policy_file_content = checked_policy_path.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        policy_file_content = checked_policy_path.read_text(encoding='cp1251', errors='ignore')
    
    
    lines_without_comments = []
    for line in policy_file_content.split('\n'):
        stripped = line.strip()
        if not stripped.startswith('#'):
            lines_without_comments.append(line)
    cleaned_content = '\n'.join(lines_without_comments)
    
    # Считаем deny[msg] {
    pattern = r'deny\[msg\]\s*\{'
    matches = re.findall(pattern, cleaned_content)
    total_deny_rules = len(matches)
    
    print(f"    Найдено правил deny[msg]: {total_deny_rules}")
    
    
    print(f"    DEBUG: Все найденные политики:")
    for i, line in enumerate(policy_file_content.split('\n'), 1):
        if re.match(r'^\s*deny\[msg\]', line):
            
            code_match = re.search(r'\[([A-Z]{2,}_\d[\w_]*)\]', line)
            if not code_match:
               
                next_lines = '\n'.join(policy_file_content.split('\n')[i:i+5])
                code_match = re.search(r'\[([A-Z]{2,}_\d[\w_]*)\]', next_lines)
            code = code_match.group(1) if code_match else "UNKNOWN"
            print(f"      {i}. {code}")
   
    
    all_files_to_check = list(set(files_from_policy + args.files))
    
    if all_files_to_check:
        print(f"    Всего файлов для проверки прав: {len(all_files_to_check)}")
        for f in all_files_to_check:
            print(f"      - {f}")
    else:
        print("     Файлы для проверки прав не найдены")


    files_data = {}
    unchecked_permissions = []
    unchecked_owners = []
    
    if all_files_to_check:
        print("\n1. Проверка прав доступа к файлам...")
        
        files_data, unchecked_permissions, unchecked_owners = check_actual_file_permissions(
            files_to_check_list=all_files_to_check, 
            docker_id=active_docker_id if is_docker_container_mode else None,
            temp_image_container_id=active_docker_id if is_docker_image_mode else None
        )
    else:
        print("\n1.  Проверка прав на файлы пропущена (файлы не указаны)")

    print("\n2. Парсинг конфигурационного файла и конвертация в JSON...")
    try:
        input_data = parse_config_to_conftest_input(config_path, files_data=files_data)
        
        
        if expected_config_keys:
            
            policy_expected_values = extract_expected_values_from_rego(checked_policy_path)
            
            config_keys = set(input_data.get('config', {}).keys())
            
            
            for expected_key, policy_codes in expected_config_keys_with_codes.items():
                if expected_key not in config_keys:
                   
                    for policy_code in policy_codes:
                        # Получаем ожидаемое значение для КОНКРЕТНОЙ политики
                        if expected_key in policy_expected_values and policy_code in policy_expected_values[expected_key]:
                            expected_value = policy_expected_values[expected_key][policy_code]
                        else:
                            expected_value = "не указано"
                        
                        
                        missing_key = f"{expected_key} [{policy_code}]"
                        missing_keys[missing_key] = expected_value
                        missing_keys_policy_codes[missing_key] = policy_code
            
            if missing_keys:
                print(f"    Найдено отсутствующих параметров: {len(missing_keys)}")
            else:
                print(f"    Все ожидаемые параметры присутствуют в конфиге")
      
        
        temp_input_json = output_path.parent / "temp_input.json"
        temp_input_json.parent.mkdir(parents=True, exist_ok=True)
        
        with open(temp_input_json, 'w', encoding='utf-8') as f:
            json.dump(input_data, f, indent=2, ensure_ascii=False, default=str)
        print(f"    Промежуточный файл создан: {temp_input_json}")
        print(f"    Тип конфигурации: {input_data.get('metadata', {}).get('file_type', 'не определен')}")
    except Exception as e:
        print(f"    Ошибка при парсинге конфига: {e}")
        if temp_container_id:
            remove_temp_container(temp_container_id, temp_container_name)
        if temp_dir: shutil.rmtree(temp_dir)
        sys.exit(1)


    print("\n3. Запуск Conftest для проверки политик...")
    violations = []
    conftest_results = None
    returncode = 0
    stderr = ""
    conftest_failures = 0
    
    try:
        stdout, stderr, returncode = run_conftest(temp_input_json, checked_policy_path)
        print(f"   Exit code: {returncode}")
        
        if stderr and 'errors occurred' in stderr.lower():
            print(f"    КРИТИЧЕСКАЯ ОШИБКА: Conftest не смог загрузить политики")
            print(f"    STDERR: {stderr[:500]}")
            final_report = {
                "timestamp": datetime.now().isoformat(),
                "config_file": config_path_str,
                "policy_file": str(checked_policy_path),
                "conftest_exit_code": returncode,
                "violations_found": False,
                "violations_count": 0,
                "violations": [],
                "unchecked_permissions_count": len(unchecked_permissions),
                "unchecked_owners_count": len(unchecked_owners),
                "unchecked_permissions": unchecked_permissions,
                "unchecked_owners": unchecked_owners,
                "error": {"type": "policy_load_error", "message": "Не удалось загрузить политики Rego", "stderr": stderr}
            }
            save_report(final_report, output_path)
            if temp_input_json.exists():
                temp_input_json.unlink()
            if temp_container_id:
                remove_temp_container(temp_container_id, temp_container_name)
            if temp_dir: shutil.rmtree(temp_dir)
            sys.exit(1)
        
        if stdout.strip():
            print(f"    STDOUT получен ({len(stdout)} символов)")
            try:
                conftest_results = json.loads(stdout)
                
                violations = format_violations(conftest_results, missing_keys=missing_keys, missing_keys_policy_codes=missing_keys_policy_codes)
                print(f"    Найдено нарушений: {len(violations)}")
                
                if isinstance(conftest_results, list):
                    # Подсчет нарушений из conftest (failures)
                    conftest_failures = sum(len(r.get('failures', [])) for r in conftest_results)
                    print(f"    Проваленных проверок (из conftest): {conftest_failures}")
                    
                    
            except json.JSONDecodeError as e:
                print(f"     WARNING: Не удалось распарсить stdout как JSON: {e}")
                violations = format_violations({"raw_output": stdout}, missing_keys=missing_keys, missing_keys_policy_codes=missing_keys_policy_codes)
                conftest_results = {"raw_text_output": stdout}
                conftest_failures = 0
        else:
            print(f"    STDOUT пуст")
            if returncode == 0:
                print("    Нарушений не найдено")
            conftest_results = {"message": "Conftest не вернул данных в stdout"}
            conftest_failures = 0

    except Exception as e:
        print(f"    Ошибка при выполнении Conftest: {e}")
        import traceback
        traceback.print_exc()
        if temp_container_id:
            remove_temp_container(temp_container_id, temp_container_name)
        if temp_dir: shutil.rmtree(temp_dir)
        sys.exit(1)

    print("\n4. Формирование отчета...")
    
   
    missing_count = len(missing_keys)
    unchecked_permissions_count = len(unchecked_permissions)
    unchecked_owners_count = len(unchecked_owners)
    
  
    total_policies = total_deny_rules
    
   
    failed_policies = conftest_failures
    
   
    missing_policies = missing_count
    
  
    unchecked_files_policies = unchecked_permissions_count + unchecked_owners_count
    
   
    passed_policies = total_policies - failed_policies - missing_policies - unchecked_files_policies
    
 
    total_errors = failed_policies + missing_policies
   
    
    clean_details = []
    if isinstance(conftest_results, list):
        for result in conftest_results:
            clean_details.append({
                "filename": result.get('filename', ''),
                "namespace": result.get('namespace', ''),
                "successes": result.get('successes', 0)
            })
    else:
        clean_details = conftest_results

    # Определение источника для отчета
    report_source_id = None
    report_source_type = "local"
    if is_docker_container_mode:
        report_source_id = args.docker_id
        report_source_type = "running_container"
    elif is_docker_image_mode:
        report_source_id = args.image
        report_source_type = "image"

   
    final_report = {
        "timestamp": datetime.now().isoformat(),
        "config_file": config_path_str,
        "policy_file": str(checked_policy_path),
        "source_type": report_source_type,
        "source_identifier": report_source_id,
        "conftest_exit_code": returncode,
        "violations_found": returncode != 0 or len(violations) > 0,
        "violations_count": len(violations),
        "summary": {
            "total_policies_in_rego_file": total_policies,
            "successfully_passed_policies": passed_policies,
            "failed_policies": failed_policies,
            "missing_policies": missing_policies,
            "unchecked_permissions": unchecked_permissions_count,
            "unchecked_owners": unchecked_owners_count,
            "total_errors": total_errors
        },
        "missing_parameters": list(missing_keys.keys()),
        "missing_parameters_details": missing_keys,
        "unchecked_permissions_list": unchecked_permissions,
        "unchecked_owners_list": unchecked_owners,
        "violations": violations,
        "details": clean_details,
        "metadata": input_data.get('metadata', {})
    }

    
    if stderr:
        final_report["stderr"] = stderr

    save_report(final_report, output_path)
    
    if temp_input_json.exists():
        temp_input_json.unlink()
    
    # Очистка временных ресурсов
    if temp_dir:
        print(f"   Очистка временных файлов: {temp_dir}")
        shutil.rmtree(temp_dir)
    
    # Удаление временного контейнера, если он был создан из образа
    if temp_container_id:
        remove_temp_container(temp_container_id, temp_container_name)

    print("\n" + "=" * 70)
    print("                         РЕЗУЛЬТАТЫ ПРОВЕРКИ")
    print("=" * 70)
    
   
    print(f"\n   ВСЕГО ПОЛИТИК В ФАЙЛЕ REGO: {total_policies}")
    print(f"   УСПЕШНО ПРОЙДЕННЫЕ ПОЛИТИКИ: {passed_policies}")
    print(f"   НЕ УСПЕШНО ПРОЙДЕННЫЕ ПОЛИТИКИ: {failed_policies}")
    print(f"   ОТСУТСТВУЮЩИЕ ПОЛИТИКИ: {missing_policies}")
    print(f"   НЕ ПРОВЕРЕНЫ ПРАВА НА ФАЙЛЫ: {unchecked_permissions_count}")
    print(f"   НЕ ПРОВЕРЕНЫ ВЛАДЕЛЬЦЫ НА ФАЙЛЫ: {unchecked_owners_count}")
    print(f"   ВСЕГО ОШИБОК: {total_errors}")
  
    
    if len(violations) > 0 or len(unchecked_permissions) > 0 or len(unchecked_owners) > 0:
        print(f"\n ВНИМАНИЕ: Обнаружены проблемы при проверке!")
        
        
        
        if len(unchecked_permissions) > 0:
            print(f"\n   Файлы, права на которые не были проверены:")
            for i, f in enumerate(unchecked_permissions, 1):
                print(f"     {i}. {f}")
        
        if len(unchecked_owners) > 0:
            print(f"\n   Файлы, владельцы которых не были проверены:")
            for i, f in enumerate(unchecked_owners, 1):
                print(f"     {i}. {f}")
        
        if violations:
            print("\n   Список нарушений:")
            for i, violation in enumerate(violations, 1):
                print(f"\n   {i}. [{violation.get('policy_code', 'N/A')}] {violation.get('category', 'Без категории')}")
                msg_preview = violation.get('message', 'Нет описания')
                print(f"      Сообщение: {msg_preview[:100]}{'...' if len(msg_preview) > 100 else ''}")
                if violation.get('expected'):
                    print(f"      Ожидалось: {violation.get('expected')}")
            
            if len(violations) > 10:
                print(f"\n   ... и еще {len(violations) - 10} нарушений (см. файл результата)")
    else:
        print("\n   Все политики безопасности соблюдены!")
    
    print("\n" + "=" * 70)
    print(f"Подробный отчет сохранен в: {output_path}")
    print("=" * 70 + "\n")
    
    if returncode != 0 or len(violations) > 0:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()