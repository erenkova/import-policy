import pandas as pd
import sys

print("=== ЧТЕНИЕ EXCEL ФАЙЛА ===")
try:
    df = pd.read_excel('test_ngx.xlsx')
    print(f"✓ Файл прочитан успешно!")
    print(f"✓ Количество строк: {len(df)}")
    print(f"✓ Количество колонок: {len(df.columns)}")
    
    print("\n=== НАЗВАНИЯ КОЛОНОК ===")
    for i, col in enumerate(df.columns):
        print(f"{i}: '{col}' (тип: {type(col).__name__})")
    
    print("\n=== ПЕРВЫЕ 3 СТРОКИ ДАННЫХ ===")
    print(df.head(3).to_string())
    
    print("\n=== ПРОВЕРКА ОБЯЗАТЕЛЬНЫХ КОЛОНОК ===")
    required = ['req_id', 'check_target']
    for col in required:
        if col in df.columns:
            print(f"✓ Колонка '{col}' найдена")
        else:
            print(f"✗ Колонка '{col}' НЕ найдена!")
            
except Exception as e:
    print(f"✗ ОШИБКА: {e}")
    import traceback
    traceback.print_exc()