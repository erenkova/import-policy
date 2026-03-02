package main

# Nginx Security Policy
# Generated from Excel
# Compatible with Conftest v0.40+ / OPA v0.60+


violation_PROM_0001[result] {
    input.config.scheme != "https"
    result := {
        "msg": "[Шифрование] Настройка шифрования трафика TLS между экспортерами и Prometheus: Ожидалось https",
        "id": "PROM_0001"
    }
}

violation_PROM_0001b[result] {
    not input.config.tls_config.min_version in ["TLS12", "TLS13"]
    result := {
        "msg": "[Шифрование] Настройка минимальной версии TLS 1.2: Ожидалось один из: TLS12, TLS13",
        "id": "PROM_0001b"
    }
}

violation_PROM_0002[result] {
    not input.config.log_level in ["warning", "error", "info", "debug"]
    result := {
        "msg": "[Логирование] Настройка уровня детализации логирования: Ожидалось один из: warning, error, info, debug",
        "id": "PROM_0002"
    }
}

violation_PROM_0003[result] {
    input.config.scrape_interval != "15s"
    result := {
        "msg": "[Сеть] Настройка интервала опроса scrape_interval: Ожидалось 15s",
        "id": "PROM_0003"
    }
}

violation_PROM_0004[result] {
    input.config.scrape_timeout != "15s"
    result := {
        "msg": "[Сеть] Настройка таймаута опроса scrape_timeout: Ожидалось 15s",
        "id": "PROM_0004"
    }
}

violation_PROM_0005[result] {
    input.files["/etc/prometheus/*.yml"].permissions != 640.0
    result := {
        "msg": "[Файловая система] Права на файл конфигурации Prometheus: Файл /etc/prometheus/*.yml должен иметь права 640.0",
        "id": "PROM_0005"
    }
}

violation_PROM_0006[result] {
    input.files["/var/lib/prometheus"].permissions != 750.0
    result := {
        "msg": "[Файловая система] Права на файл хранения данных Prometheus: Файл /var/lib/prometheus должен иметь права 750.0",
        "id": "PROM_0006"
    }
}

violation_PROM_0007[result] {
    input.files["/etc/prometheus/*.yml"].owner != "prometheus"
    result := {
        "msg": "[Файловая система] Владелец файлов конфигурации Prometheus: Файл /etc/prometheus/*.yml должен принадлежать prometheus",
        "id": "PROM_0007"
    }
}

violation_PROM_0008[result] {
    input.config.web.enable-admin-api != false
    result := {
        "msg": "[Разграничение доступа] Отключение отладочных endpoints в production: Ожидалось False",
        "id": "PROM_0008"
    }
}

violation_PROM_0009[result] {
    input.config.web.config.file != null
    result := {
        "msg": "[Аутентификация] Настройка аутентификации для доступа к Prometheus: Ожидалось nan",
        "id": "PROM_0009"
    }
}

violation_PROM_0010[result] {
    input.config.web.tls_cert_file != null
    result := {
        "msg": "[Шифрование] Настройка TLS для веб-интерфейса Prometheus: Ожидалось nan",
        "id": "PROM_0010"
    }
}

violation_PROM_0011[result] {
    input.config.web.tls_key_file != null
    result := {
        "msg": "[Шифрование] Настройка TLS ключа для веб-интерфейса Prometheus: Ожидалось nan",
        "id": "PROM_0011"
    }
}

violation_PROM_0012[result] {
    input.files["/etc/prometheus/cert/*.key"].permissions != 400.0
    result := {
        "msg": "[Шифрование] Права на файл TLS ключа Prometheus: Файл /etc/prometheus/cert/*.key должен иметь права 400.0",
        "id": "PROM_0012"
    }
}
