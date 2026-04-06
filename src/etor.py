#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Конвертер таблиц требований безопасности в Rego файлы для conftest
Исправленная версия с корректной обработкой строк и экранированием кавычек
"""

import pandas as pd
import re
import sys
import glob
import json
from pathlib import Path
from typing import Dict, List, Any, Optional


class RegoConverter:
    def __init__(self):
        self.helper_functions = {}
        self.generated_rules = []
        self.file_permission_rules = []
        
    def read_table(self, file_path: str) -> pd.DataFrame:
        """Чтение таблицы из Excel или CSV"""
        if file_path.endswith('.xlsx'):
            df = pd.read_excel(file_path, sheet_name=0)
        elif file_path.endswith('.csv'):
            df = pd.read_csv(file_path)
        else:
            raise ValueError("Поддерживаются только .xlsx и .csv файлы")
        
        # Нормализация имен колонок
        df.columns = df.columns.str.strip()
        return df
    
    def sanitize_key(self, key: str) -> str:
        """Преобразование ключа конфигурации в валидный Rego идентификатор"""
        if not key:
            return "unknown"
        # Замена точек и других спецсимволов на подчеркивания
        sanitized = re.sub(r'[^a-zA-Z0-9_]', '_', str(key))
        # Если начинается с цифры, добавляем префикс
        if sanitized and sanitized[0].isdigit():
            sanitized = 'cfg_' + sanitized
        return sanitized.lower()
    
    def escape_rego_string(self, value: str) -> str:
        """Экранирование специальных символов для Rego строк"""
        if not value:
            return ""
        # Экранирование обратных слешей
        value = value.replace('\\', '\\\\')
        # Экранирование двойных кавычек
        value = value.replace('"', '\\"')
        # Экранирование новых строк
        value = value.replace('\n', '\\n')
        # Экранирование табуляции
        value = value.replace('\t', '\\t')
        return value
    
    def is_pure_numeric_value(self, value: str) -> bool:
        """
        Проверка, является ли значение ЧИСТЫМ числом (без букв после цифр)
        "10" -> True
        "1d", "2m", "5r/s" -> False (это строки)
        """
        if value is None or value == '':
            return False
        
        value = str(value).strip()
        
        # Если есть буквы после цифр - это не чистое число
        if re.search(r'\d+[a-zA-Z]', value):
            return False
        
        # Пробуем распарсить как число
        try:
            float(value.replace(',', '.'))
            return True
        except:
            return False
    
    def is_inverse_check(self, expected_value: str) -> bool:
        """Проверка на инверсную проверку (!=)"""
        if expected_value is None or expected_value == '':
            return False
        return str(expected_value).strip().startswith('!=')
    
    def get_inverse_value(self, expected_value: str) -> str:
        """Получение значения для инверсной проверки"""
        return str(expected_value).strip()[2:].strip()
    
    def generate_helper_function(self, func_name: str, allowed_values: List[str], 
                                  check_type: str = 'exact') -> str:
        """Генерация вспомогательной функции для проверки списка значений"""
        func_key = f"{func_name}:{check_type}:{','.join(sorted(allowed_values))}"
        
        if func_key in self.helper_functions:
            return func_name
        
        self.helper_functions[func_key] = True
        
        # Экранируем значения для списка
        values_str = ', '.join([f'"{self.escape_rego_string(v)}"' for v in allowed_values])
        
        if check_type == 'contains':
            func_code = f"""
{func_name}(value) {{
    allowed := [{values_str}]
    some v in allowed
    contains(lower(sprintf("%v", [value])), v)
}}
"""
        else:
            func_code = f"""
{func_name}(value) {{
    allowed := [{values_str}]
    some v in allowed
    sprintf("%v", [value]) == v
}}
"""
        
        return func_code
    
    def generate_config_rule(self, row: Dict[str, Any]) -> str:
        """Генерация правила для проверки конфигурационного параметра"""
        req_id = str(row.get('req_id', 'UNKNOWN')).strip()
        req_name = str(row.get('req_name', 'Без названия')).strip()
        category = str(row.get('category', 'Общее')).strip()
        config_key = str(row.get('config_key_path', '')).strip() if pd.notna(row.get('config_key_path')) else ''
        expected_value = str(row.get('expected_value', '')).strip() if pd.notna(row.get('expected_value')) else ''
        expected_values_list = str(row.get('expected_values_list', '')).strip() if pd.notna(row.get('expected_values_list')) else ''
        
        if not config_key:
            return ""
        
        # Санитизация ключа для Rego
        config_key_sanitized = self.sanitize_key(config_key)
        
        # Определение типа проверки
        is_inverse = self.is_inverse_check(expected_value)
        has_value_list = bool(expected_values_list and expected_values_list != '')
        
        # Формирование условия проверки
        if has_value_list:
            # Проверка по списку разрешенных значений
            allowed_values = [v.strip() for v in expected_values_list.split(',') if v.strip()]
            func_name = f"any_allowed_{config_key_sanitized}"
            
            # Определение типа проверки (contains или exact)
            check_keywords = ['ssl_protocols', 'limit_except', 'sql_mode', 'log_statement', 
                            'log_error_verbosity', 'auth_backends', 'tls_version']
            check_type = 'contains' if any(kw in config_key.lower() for kw in check_keywords) else 'exact'
            
            helper_func = self.generate_helper_function(func_name, allowed_values, check_type)
            self.generated_rules.append(helper_func)
            
            condition = f"not {func_name}(input.config.{config_key_sanitized})"
            msg_text = f"Ожидалось значение из списка [{expected_values_list}]"
                
        elif is_inverse:
            # Инверсная проверка (!=) - ошибка если значение РАВНО запрещенному
            inverse_val = self.get_inverse_value(expected_value)
            if self.is_pure_numeric_value(inverse_val):
                condition = f"input.config.{config_key_sanitized} == {inverse_val}"
            else:
                escaped_val = self.escape_rego_string(inverse_val.lower())
                condition = f"lower(input.config.{config_key_sanitized}) == \"{escaped_val}\""
            msg_text = f"Запрещено значение {config_key} = {inverse_val}"
        else:
            # Обычная проверка
            if expected_value:
                # Очистка значения от точек с запятой в конце
                clean_value = expected_value.replace(';', '').strip()
                
                # Проверяем, является ли значение чистым числом (без букв)
                if self.is_pure_numeric_value(clean_value):
                    condition = f"input.config.{config_key_sanitized} != {clean_value}"
                elif config_key.lower() in ['add_header', 'proxy_set_header', 'proxy_hide_header', 
                                           'location', 'limit_conn_zone', 'limit_conn', 'limit_req_zone', 
                                           'large_client_header_buffers', 'error_log', 'access_log', 
                                           'listen', 'ssl_certificate', 'ssl_ciphers', 'log_line_prefix']:
                    # Проверка через contains для сложных строк с экранированием кавычек
                    escaped_val = self.escape_rego_string(clean_value.lower())
                    condition = f"not contains(lower(input.config.{config_key_sanitized}), \"{escaped_val}\")"
                else:
                    # Обычное строковое сравнение с экранированием
                    escaped_val = self.escape_rego_string(clean_value.lower())
                    condition = f"lower(input.config.{config_key_sanitized}) != \"{escaped_val}\""
                
                msg_text = f"Ожидалось {config_key} = {clean_value}"
            else:
                condition = f"not input.config.{config_key_sanitized}"
                msg_text = f"Ожидалось наличие параметра {config_key}"
        
        # Экранируем сообщение об ошибке
        escaped_msg = self.escape_rego_string(msg_text)
        
        rule = f"""
deny[msg] {{
    input.config.{config_key_sanitized}
    {condition}
    msg := "[{category}] {req_name}: {escaped_msg} [{req_id}]"
}}
"""
        return rule
    
    def generate_file_permission_rule(self, row: Dict[str, Any]) -> List[str]:
        """Генерация правил для проверки прав на файлы"""
        rules = []
        
        req_id = str(row.get('req_id', 'UNKNOWN')).strip()
        req_name = str(row.get('req_name', 'Без названия')).strip()
        category = str(row.get('category', 'Общее')).strip()
        file_path_pattern = str(row.get('file_path_pattern', '')).strip() if pd.notna(row.get('file_path_pattern')) else ''
        expected_permissions = str(row.get('expected_permissions', '')).strip() if pd.notna(row.get('expected_permissions')) else ''
        expected_owner = str(row.get('expected_owner', '')).strip() if pd.notna(row.get('expected_owner')) else ''
        
        if not file_path_pattern:
            return rules
        
        # Экранирование пути к файлу
        escaped_path = self.escape_rego_string(file_path_pattern)
        
        # Проверка прав (permissions)
        if expected_permissions:
            rule_perm = f"""
deny[msg] {{
    input.files["{escaped_path}"]
    input.files["{escaped_path}"].permissions != "{expected_permissions}"
    msg := "[{category}] {req_name}: Ожидалось permissions = {expected_permissions} [{req_id}A]"
}}
"""
            rules.append(rule_perm)
        
        # Проверка владельца (owner)
        if expected_owner:
            rule_owner = f"""
deny[msg] {{
    input.files["{escaped_path}"]
    input.files["{escaped_path}"].owner != "{expected_owner}"
    msg := "[{category}] {req_name}: Ожидалось owner = {expected_owner} [{req_id}B]"
}}
"""
            rules.append(rule_owner)
        
        return rules
    
    def generate_header_check_rules(self, df: pd.DataFrame) -> List[str]:
        """Генерация специальных правил для заголовков (add_header)"""
        rules = []
        header_types = set()
        
        for _, row in df.iterrows():
            config_key = str(row.get('config_key_path', '')).strip() if pd.notna(row.get('config_key_path')) else ''
            expected_value = str(row.get('expected_value', '')).strip() if pd.notna(row.get('expected_value')) else ''
            
            if config_key.lower() == 'add_header' and expected_value:
                # Извлечение имени заголовка
                header_match = re.search(r'([A-Za-z\-]+)\s+', expected_value)
                if header_match:
                    header_name = header_match.group(1).lower()
                    if header_name not in header_types:
                        header_types.add(header_name)
        
        if header_types:
            helper_func = """
any_header_contains(headers, header_name) {
    some h in headers
    contains(lower(h), header_name)
}
"""
            self.generated_rules.append(helper_func)
            
            for _, row in df.iterrows():
                config_key = str(row.get('config_key_path', '')).strip() if pd.notna(row.get('config_key_path')) else ''
                expected_value = str(row.get('expected_value', '')).strip() if pd.notna(row.get('expected_value')) else ''
                
                if config_key.lower() == 'add_header' and expected_value:
                    header_match = re.search(r'([A-Za-z\-]+)\s+', expected_value)
                    if header_match:
                        header_name = header_match.group(1).lower()
                        req_id = str(row.get('req_id', 'UNKNOWN')).strip()
                        req_name = str(row.get('req_name', 'Без названия')).strip()
                        category = str(row.get('category', 'Общее')).strip()
                        
                        # Экранируем значение для contains проверки
                        escaped_val = self.escape_rego_string(expected_value.lower())
                        
                        rule = f"""
deny[msg] {{
    input.config.add_header
    not contains(lower(input.config.add_header), "{escaped_val}")
    msg := "[{category}] {req_name}: Ожидалось add_header = {self.escape_rego_string(expected_value)} [{req_id}]"
}}
"""
                        rules.append(rule)
        
        return rules
    
    def convert(self, input_file: str, output_file: str) -> str:
        """Основной метод конвертации"""
        # Чтение таблицы
        df = self.read_table(input_file)
        
        # Сброс состояния
        self.helper_functions = {}
        self.generated_rules = []
        self.file_permission_rules = []
        config_rules = []
        
        # Обработка каждой строки
        for _, row in df.iterrows():
            check_target = str(row.get('check_target', '')).strip() if pd.notna(row.get('check_target')) else ''
            
            if check_target == 'config_parameter':
                rule = self.generate_config_rule(row)
                if rule:
                    config_rules.append(rule)
            elif check_target == 'file_permissions':
                rules = self.generate_file_permission_rule(row)
                self.file_permission_rules.extend(rules)
        
        # Проверка на специальные заголовки
        header_rules = self.generate_header_check_rules(df)
        
        # Формирование итогового файла Rego
        rego_content = """package main
import future.keywords.in

"""
        
        # Добавление вспомогательных функций
        for func in self.generated_rules:
            rego_content += func + "\n"
        
        # Добавление правил для конфигов
        for rule in config_rules:
            rego_content += rule + "\n"
        
        # Добавление правил для заголовков (если есть)
        for rule in header_rules:
            rego_content += rule + "\n"
        
        # Добавление правил для прав на файлы
        for rule in self.file_permission_rules:
            rego_content += rule + "\n"
        
        # Запись в файл
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(rego_content)
        
        return rego_content
    
    def expand_glob_patterns(self, input_files: List[str]) -> List[str]:
        """Разворачивание glob-паттернов в списке файлов"""
        expanded_files = []
        for pattern in input_files:
            matched = glob.glob(pattern)
            if matched:
                expanded_files.extend(matched)
            else:
                # Если паттерн не найден, добавляем как есть (будет ошибка)
                expanded_files.append(pattern)
        return expanded_files
    
    def convert_multiple(self, input_files: List[str], output_dir: str) -> Dict[str, str]:
        """Конвертация нескольких таблиц"""
        # Разворачиваем glob-паттерны
        expanded_files = self.expand_glob_patterns(input_files)
        
        if not expanded_files:
            raise ValueError("Не найдено файлов по указанным паттернам")
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        results = {}
        for input_file in expanded_files:
            file_name = Path(input_file).stem
            output_file = output_dir / f"{file_name}.rego"
            
            try:
                self.convert(input_file, str(output_file))
                results[input_file] = str(output_file)
                print(f"✓ Конвертировано: {input_file} -> {output_file}")
            except Exception as e:
                print(f"✗ Ошибка при конвертации {input_file}: {e}")
                results[input_file] = f"ERROR: {e}"
        
        return results


def main():
    """Точка входа"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Конвертер таблиц требований безопасности в Rego файлы'
    )
    parser.add_argument(
        'input_files',
        nargs='+',
        help='Входные файлы таблиц (.xlsx или .csv). Поддерживаются glob-паттерны (*, ?)'
    )
    parser.add_argument(
        '-o', '--output-dir',
        default='./rego_policies',
        help='Директория для выходных Rego файлов (по умолчанию: ./rego_policies)'
    )
    
    args = parser.parse_args()
    
    converter = RegoConverter()
    results = converter.convert_multiple(args.input_files, args.output_dir)
    
    print("\n" + "="*60)
    print("Результаты конвертации:")
    print("="*60)
    for input_file, output_file in results.items():
        print(f"{input_file} -> {output_file}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())