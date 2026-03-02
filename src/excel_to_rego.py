import pandas as pd
import sys
import os
import json
import re

def sanitize_id(req_id):
    """Превращает ID в валидное имя переменной Rego"""
    if pd.isna(req_id):
        return "unknown_rule"
    return re.sub(r'[^a-zA-Z0-9]', '_', str(req_id))

def parse_list_value(list_str):
    """Парсит строку списка 'val1,val2' в массив Rego"""
    if pd.isna(list_str) or str(list_str).strip() == '':
        return []
    items = [str(x).strip() for x in str(list_str).split(',')]
    return json.dumps(items)

def format_rego_value(val):
    """Форматирует значение для Rego"""
    if pd.isna(val):
        return "null"
    s_val = str(val).strip().lower()
    if s_val in ['true', 'false']:
        return s_val
    if s_val.isdigit():
        return str(val)
    return f'"{val}"'

def generate_config_rule(row):
    """Генерация правила для config_parameter"""
    req_id = sanitize_id(row.get('req_id', 'unknown'))
    path = str(row.get('config_key_path', '')).strip()
    exp_value = row.get('expected_value')
    exp_list = row.get('expected_values_list')
    req_name = str(row.get('req_name', 'Check'))
    category = str(row.get('category', 'General'))
    
    if pd.isna(path) or path == '':
        return None, "Пустой config_key_path"
    
    rego_path = f"input.config.{path}"
    
    # Определяем тип проверки
    if not pd.isna(exp_list) and str(exp_list).strip() != '':
        val = parse_list_value(exp_list)
        condition = f"not {rego_path} in {val}"
        expected_desc = f"один из: {exp_list}"
    else:
        val = format_rego_value(exp_value)
        condition = f"{rego_path} != {val}"
        expected_desc = f"{exp_value}"
    
    msg = f"[{category}] {req_name}: Ожидалось {expected_desc}"
    
    rule_name = f"violation_{req_id}"
    safe_msg = msg.replace('"', '\\"')
    
    rule = f"""
{rule_name}[result] {{
    {condition}
    result := {{
        "msg": "{safe_msg}",
        "id": "{req_id}"
    }}
}}
"""
    return rule, None

def generate_file_rule(row, check_type):
    """Генерация правила для file_permissions/file_owner"""
    req_id = sanitize_id(row.get('req_id', 'unknown'))
    file_pattern = str(row.get('file_path_pattern', '')).strip()
    req_name = str(row.get('req_name', 'File Check'))
    category = str(row.get('category', 'FileSystem'))
    
    if pd.isna(file_pattern) or file_pattern == '':
        return None, "Пустой file_path_pattern"
    
    file_access = f'input.files["{file_pattern}"]'
    
    if check_type == 'file_permissions':
        perms = str(row.get('expected_permissions', '')).strip()
        if pd.isna(perms) or perms == '':
            return None, "Пустой expected_permissions"
        condition = f"{file_access}.permissions != {perms}"
        msg = f"[{category}] {req_name}: Файл {file_pattern} должен иметь права {perms}"
        
    elif check_type == 'file_owner':
        owner = str(row.get('expected_owner', '')).strip()
        if pd.isna(owner) or owner == '':
            return None, "Пустой expected_owner"
        condition = f'{file_access}.owner != "{owner}"'
        msg = f"[{category}] {req_name}: Файл {file_pattern} должен принадлежать {owner}"
    
    rule_name = f"violation_{req_id}"
    safe_msg = msg.replace('"', '\\"')
    
    return f"""
{rule_name}[result] {{
    {condition}
    result := {{
        "msg": "{safe_msg}",
        "id": "{req_id}"
    }}
}}
""", None

def convert_excel_to_rego(excel_path, output_path):
    print(f"Чтение файла: {excel_path}")
    
    if not os.path.exists(excel_path):
        print(f"✗ Ошибка: Файл {excel_path} не найден")
        return False
    
    try:
        # Читаем Excel - первая строка заголовки
        df = pd.read_excel(excel_path)
        print(f"✓ Прочитано {len(df)} строк")
        
        # Проверяем обязательные колонки
        if 'req_id' not in df.columns:
            print("✗ Ошибка: Отсутствует колонка 'req_id'")
            print(f"  Доступные колонки: {df.columns.tolist()}")
            return False
        
        if 'check_target' not in df.columns:
            print("✗ Ошибка: Отсутствует колонка 'check_target'")
            return False
        
        rego_header = """package main

# Nginx Security Policy
# Generated from Excel
# Compatible with Conftest v0.40+ / OPA v0.60+

"""
        
        rules_content = ""
        success_count = 0
        error_count = 0
        
        for index, row in df.iterrows():
            try:
                check_target = str(row.get('check_target', '')).strip()
                
                if pd.isna(check_target) or check_target == '':
                    print(f"  Строка {index}: пропущена (пустой check_target)")
                    error_count += 1
                    continue
                
                rule = None
                error = None
                
                if check_target == 'config_parameter':
                    rule, error = generate_config_rule(row)
                elif check_target == 'file_permissions':
                    rule, error = generate_file_rule(row, 'file_permissions')
                elif check_target == 'file_owner':
                    rule, error = generate_file_rule(row, 'file_owner')
                else:
                    error = f"Неизвестный check_target: {check_target}"
                
                if error:
                    print(f"  Строка {index} ({row.get('req_id', 'N/A')}): {error}")
                    error_count += 1
                elif rule:
                    rules_content += rule
                    success_count += 1
                    
            except Exception as e:
                print(f"  Строка {index}: ошибка {e}")
                error_count += 1
                continue
        
        # Записываем файл
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(rego_header + rules_content)
        
        print(f"\n✓ Успешно! Сгенерировано правил: {success_count}")
        print(f"  Ошибок/пропущено: {error_count}")
        print(f"  Файл сохранен: {output_path}")
        return True
        
    except Exception as e:
        print(f"✗ Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    
    excel_dir = os.path.join(project_root, "excel_tables")
    rego_dir = os.path.join(project_root, "rego_policies")
    
    if len(sys.argv) < 3:
        print("Использование:")
        print("  python src/excel_to_rego.py <input.xlsx> <output.rego>")
        print("  python src/excel_to_rego.py security_policies.xlsx policy_security.rego")
        print("\nФайлы ищутся в папках:")
        print(f"  Excel: {excel_dir}")
        print(f"  Rego:  {rego_dir}")
        sys.exit(1)
    
    input_filename = sys.argv[1]
    output_filename = sys.argv[2]

    if not os.path.isabs(input_filename):
        input_file = os.path.join(excel_dir, input_filename)
    else:
        input_file = input_filename
    
    if not os.path.isabs(output_filename):
        output_file = os.path.join(rego_dir, output_filename)
    else:
        output_file = output_filename
    
    success = convert_excel_to_rego(input_file, output_file)
    sys.exit(0 if success else 1)