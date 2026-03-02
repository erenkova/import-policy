package main

# Nginx Security Policy
# Generated from Excel
# Compatible with Conftest v0.40+ / OPA v0.60+


violation_NGLUX_0001[result] {
    input.config.load_module != null
    result := {
        "msg": "[Модули] Отсутствие директивы load_module: Ожидалось nan",
        "id": "NGLUX_0001"
    }
}

violation_NGLUX_0002[result] {
    not input.config.gzip in ["off", ""]
    result := {
        "msg": "[Модули] Отключение модуля gzip: Ожидалось один из: off,",
        "id": "NGLUX_0002"
    }
}

violation_NGLUX_0003[result] {
    input.files["/etc/nginx"].owner != "root"
    result := {
        "msg": "[Файловая система] Владелец каталогов Nginx - root: Файл /etc/nginx должен принадлежать root",
        "id": "NGLUX_0003"
    }
}

violation_NGLUX_0003b[result] {
    input.files["/usr/share/nginx"].owner != "root"
    result := {
        "msg": "[Файловая система] Владелец каталогов Nginx - root (usr): Файл /usr/share/nginx должен принадлежать root",
        "id": "NGLUX_0003b"
    }
}

violation_NGLUX_0004[result] {
    input.files["/opt/luxmsbi/conf/nginx"].permissions != 755.0
    result := {
        "msg": "[Файловая система] Права на каталоги Nginx: Файл /opt/luxmsbi/conf/nginx должен иметь права 755.0",
        "id": "NGLUX_0004"
    }
}

violation_NGLUX_0004b[result] {
    input.files["/opt/luxmsbi/conf/nginx/*.conf"].permissions != 644.0
    result := {
        "msg": "[Файловая система] Права на файлы Nginx: Файл /opt/luxmsbi/conf/nginx/*.conf должен иметь права 644.0",
        "id": "NGLUX_0004b"
    }
}

violation_NGLUX_0005[result] {
    input.files["/var/log/nginx"].permissions != 660.0
    result := {
        "msg": "[Файловая система] Права на директорию с дампами: Файл /var/log/nginx должен иметь права 660.0",
        "id": "NGLUX_0005"
    }
}

violation_NGLUX_0005b[result] {
    input.files["/var/log/nginx"].owner != "nginx"
    result := {
        "msg": "[Файловая система] Группа директории с дампами: Файл /var/log/nginx должен принадлежать nginx",
        "id": "NGLUX_0005b"
    }
}

violation_NGLUX_0006[result] {
    not input.config.keepalive_timeout in ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "60", "61", "62", "63", "64", "65"]
    result := {
        "msg": "[Сеть] Параметр keepalive_timeout в диапазоне 1-65 секунд: Ожидалось один из: 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65",
        "id": "NGLUX_0006"
    }
}

violation_NGLUX_0007[result] {
    not input.config.location in ["deny all", "return 404"]
    result := {
        "msg": "[Разграничение доступа] Запрет раскрытия скрытых директорий: Ожидалось один из: deny all, return 404",
        "id": "NGLUX_0007"
    }
}

violation_NGLUX_0008[result] {
    not input.config.add_header in ["Strict-Transport-Security max-age=31536000"]
    result := {
        "msg": "[Шифрование] Включение HSTS с max-age 31536000: Ожидалось один из: Strict-Transport-Security max-age=31536000",
        "id": "NGLUX_0008"
    }
}

violation_NGLUX_0009[result] {
    input.config.client_max_body_size != "100m"
    result := {
        "msg": "[Ограничение запросов] Параметр client_max_body_size 100m: Ожидалось 100m",
        "id": "NGLUX_0009"
    }
}

violation_NGLUX_0010[result] {
    not input.config.large_client_header_buffers in ["2 32k"]
    result := {
        "msg": "[Ограничение запросов] Параметр large_client_header_buffers 2 32k: Ожидалось один из: 2 32k",
        "id": "NGLUX_0010"
    }
}

violation_NGLUX_0011[result] {
    not input.config.limit_req_zone in ["rate=5r/s"]
    result := {
        "msg": "[Ограничение запросов] Ограничение запросов 5 в секунду: Ожидалось один из: rate=5r/s",
        "id": "NGLUX_0011"
    }
}
