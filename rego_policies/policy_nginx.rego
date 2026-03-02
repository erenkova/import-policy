package main

# Nginx Security Policy
# Generated from Excel
# Compatible with Conftest v0.40+ / OPA v0.60+


violation_NGX_007[result] {
    input.config.User != "nginx"
    result := {
        "msg": "[Разграничение доступа] Запуск Nginx с сервисной учетной записью: Ожидалось nginx",
        "id": "NGX_007"
    }
}

violation_NGX_014[result] {
    not input.config.keepalive_timeout in ["1", "2", "3", "4", "5", "6", "7", "8", "9"]
    result := {
        "msg": "[Сеть] Параметр keepalive_timeout в диапазоне 1-9 секунд: Ожидалось один из: 1,2,3,4,5,6,7,8,9",
        "id": "NGX_014"
    }
}

violation_NGX_015[result] {
    not input.config.send_timeout in ["1", "2", "3", "4", "5", "6", "7", "8", "9"]
    result := {
        "msg": "[Сеть] Параметр send_timeout в диапазоне 1-9 секунд: Ожидалось один из: 1,2,3,4,5,6,7,8,9",
        "id": "NGX_015"
    }
}

violation_NGX_016[result] {
    input.config.server_tokens != "off"
    result := {
        "msg": "[Раскрытие информации] Отключение server_tokens: Ожидалось off",
        "id": "NGX_016"
    }
}

violation_NGX_018[result] {
    input.config.location != "deny all; return 404"
    result := {
        "msg": "[Разграничение доступа] Запрет раскрытия скрытых директорий: Ожидалось deny all; return 404",
        "id": "NGX_018"
    }
}

violation_NGX_019[result] {
    input.config.proxy_hide_header != "X-Powered-By, Server"
    result := {
        "msg": "[Раскрытие информации] Отключение заголовков reverse proxy: Ожидалось X-Powered-By, Server",
        "id": "NGX_019"
    }
}

violation_NGX_020[result] {
    input.config.log_format != null
    result := {
        "msg": "[Логирование] Настройка подробного логирования: Ожидалось nan",
        "id": "NGX_020"
    }
}

violation_NGX_021[result] {
    input.files["/etc/logrotate.d/nginx"].permissions != 644.0
    result := {
        "msg": "[Логирование] Настройка ротации журналов: Файл /etc/logrotate.d/nginx должен иметь права 644.0",
        "id": "NGX_021"
    }
}

violation_NGX_022[result] {
    input.config.error_log != "syslog:server=127.0.0.1"
    result := {
        "msg": "[Логирование] Отправка error_log на syslog сервер: Ожидалось syslog:server=127.0.0.1",
        "id": "NGX_022"
    }
}

violation_NGX_023[result] {
    input.config.access_log != "syslog:server=127.0.0.1"
    result := {
        "msg": "[Логирование] Отправка access_log на syslog сервер: Ожидалось syslog:server=127.0.0.1",
        "id": "NGX_023"
    }
}

violation_NGX_024[result] {
    input.config.proxy_set_header != "X-Real-IP, X-Forwarded-For"
    result := {
        "msg": "[Сеть] Передача IP источника при проксировании: Ожидалось X-Real-IP, X-Forwarded-For",
        "id": "NGX_024"
    }
}

violation_NGX_025[result] {
    input.config.listen != "443 ssl"
    result := {
        "msg": "[Сеть] Прослушивание только порта HTTPS 443: Ожидалось 443 ssl",
        "id": "NGX_025"
    }
}

violation_NGX_026[result] {
    input.config.ssl_certificate != null
    result := {
        "msg": "[Шифрование] Установка доверенных сертификатов: Ожидалось nan",
        "id": "NGX_026"
    }
}

violation_NGX_027[result] {
    input.files["/etc/nginx/crt/*.key"].permissions != 400.0
    result := {
        "msg": "[Шифрование] Права на файл приватного ключа: Файл /etc/nginx/crt/*.key должен иметь права 400.0",
        "id": "NGX_027"
    }
}

violation_NGX_028[result] {
    not input.config.ssl_protocols in ["TLSv1.2", "TLSv1.3"]
    result := {
        "msg": "[Шифрование] Отключение уязвимых протоколов SSL/TLS: Ожидалось один из: TLSv1.2, TLSv1.3",
        "id": "NGX_028"
    }
}

violation_NGX_029[result] {
    input.config.ssl_prefer_server_ciphers != "on"
    result := {
        "msg": "[Шифрование] Настройка безопасных шифров: Ожидалось on",
        "id": "NGX_029"
    }
}

violation_NGX_029[result] {
    input.config.ssl_ciphers != null
    result := {
        "msg": "[Шифрование] Настройка безопасных шифров (ciphers): Ожидалось nan",
        "id": "NGX_029"
    }
}

violation_NGX_030[result] {
    input.files["/etc/nginx/dhparam.pem"].permissions != 400.0
    result := {
        "msg": "[Шифрование] Права на файл Diffie-Hellman: Файл /etc/nginx/dhparam.pem должен иметь права 400.0",
        "id": "NGX_030"
    }
}

violation_NGX_031[result] {
    input.config.add_header != "Strict-Transport-Security max-age=15678000"
    result := {
        "msg": "[Шифрование] Включение HSTS: Ожидалось Strict-Transport-Security max-age=15678000",
        "id": "NGX_031"
    }
}

violation_NGX_032[result] {
    input.config.ssl_stapling != "on"
    result := {
        "msg": "[Шифрование] Настройка OCSP Stapling: Ожидалось on",
        "id": "NGX_032"
    }
}

violation_NGX_032[result] {
    input.config.ssl_stapling_verify != "on"
    result := {
        "msg": "[Шифрование] Настройка OCSP Stapling verify: Ожидалось on",
        "id": "NGX_032"
    }
}

violation_NGX_033[result] {
    input.config.ssl_session_tickets != "off"
    result := {
        "msg": "[Шифрование] Отключение ssl_session_tickets: Ожидалось off",
        "id": "NGX_033"
    }
}

violation_NGX_034[result] {
    input.config.limit_except != "GET, HEAD, OPTIONS"
    result := {
        "msg": "[Разграничение доступа] Белый список HTTP методов: Ожидалось GET, HEAD, OPTIONS",
        "id": "NGX_034"
    }
}

violation_NGX_036[result] {
    input.config.client_header_timeout != 10
    result := {
        "msg": "[Ограничение запросов] Настройка client_header_timeout: Ожидалось 10",
        "id": "NGX_036"
    }
}

violation_NGX_036[result] {
    input.config.client_body_timeout != 10
    result := {
        "msg": "[Ограничение запросов] Настройка client_body_timeout: Ожидалось 10",
        "id": "NGX_036"
    }
}

violation_NGX_037[result] {
    input.config.client_max_body_size != "2m"
    result := {
        "msg": "[Ограничение запросов] Настройка client_max_body_size: Ожидалось 2m",
        "id": "NGX_037"
    }
}

violation_NGX_038[result] {
    input.config.large_client_header_buffers != "8 32k"
    result := {
        "msg": "[Ограничение запросов] Настройка large_client_header_buffers: Ожидалось 8 32k",
        "id": "NGX_038"
    }
}

violation_NGX_039[result] {
    input.config.limit_conn_zone != null
    result := {
        "msg": "[Ограничение запросов] Ограничение подключений с одного IP: Ожидалось nan",
        "id": "NGX_039"
    }
}

violation_NGX_040[result] {
    input.config.limit_req_zone != "rate=5r/s"
    result := {
        "msg": "[Ограничение запросов] Ограничение запросов с одного IP: Ожидалось rate=5r/s",
        "id": "NGX_040"
    }
}

violation_NGX_041[result] {
    input.config.add_header != "X-Frame-Options SAMEORIGIN"
    result := {
        "msg": "[Безопасность браузера] Настройка X-Frame-Options: Ожидалось X-Frame-Options SAMEORIGIN",
        "id": "NGX_041"
    }
}

violation_NGX_042[result] {
    input.config.add_header != "X-Content-Type-Options nosniff"
    result := {
        "msg": "[Безопасность браузера] Настройка X-Content-Type-Options: Ожидалось X-Content-Type-Options nosniff",
        "id": "NGX_042"
    }
}

violation_NGX_043[result] {
    input.config.add_header != "X-XSS-Protection 1; mode=block"
    result := {
        "msg": "[Безопасность браузера] Настройка X-XSS-Protection: Ожидалось X-XSS-Protection 1; mode=block",
        "id": "NGX_043"
    }
}

violation_NGX_044[result] {
    input.config.add_header != "Content-Security-Policy"
    result := {
        "msg": "[Безопасность браузера] Настройка Content-Security-Policy: Ожидалось Content-Security-Policy",
        "id": "NGX_044"
    }
}

violation_NGX_045[result] {
    input.config.add_header != "Referrer-Policy no-referrer"
    result := {
        "msg": "[Безопасность браузера] Настройка Referrer-Policy: Ожидалось Referrer-Policy no-referrer",
        "id": "NGX_045"
    }
}
