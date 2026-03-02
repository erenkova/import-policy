package main

# Nginx Security Policy
# Generated from Excel
# Compatible with Conftest v0.40+ / OPA v0.60+


violation_NGPIX_0001[result] {
    input.config.location != "allow <IP_Магазина_данных>; deny all;"
    result := {
        "msg": "[Разграничение доступа] Ограничение доступа REST API для Магазина данных: Ожидалось allow <IP_Магазина_данных>; deny all;",
        "id": "NGPIX_0001"
    }
}

violation_NGPIX_0002[result] {
    input.config.location != "allow <IP_СКДСА>; deny all;"
    result := {
        "msg": "[Разграничение доступа] Ограничение доступа REST API для администраторов PIX BI: Ожидалось allow <IP_СКДСА>; deny all;",
        "id": "NGPIX_0002"
    }
}

violation_NGPIX_0003[result] {
    input.config.client_max_body_size != "1500m"
    result := {
        "msg": "[Ограничение запросов] Параметр client_max_body_size 1500m: Ожидалось 1500m",
        "id": "NGPIX_0003"
    }
}

violation_NGPIX_0004[result] {
    not input.config.large_client_header_buffers in ["8 64k"]
    result := {
        "msg": "[Ограничение запросов] Параметр large_client_header_buffers 8 64k: Ожидалось один из: 8 64k",
        "id": "NGPIX_0004"
    }
}

violation_NGPIX_0005[result] {
    input.config.limit_conn != "perip 100"
    result := {
        "msg": "[Ограничение запросов] Ограничение подключений 100 с одного IP: Ожидалось perip 100",
        "id": "NGPIX_0005"
    }
}

violation_NGPIX_0006[result] {
    not input.config.limit_req_zone in ["rate=10000r/s"]
    result := {
        "msg": "[Ограничение запросов] Ограничение запросов 10000 в секунду: Ожидалось один из: rate=10000r/s",
        "id": "NGPIX_0006"
    }
}

violation_NGPIX_0007[result] {
    not input.config.add_header in ["Content-Security-Policy"]
    result := {
        "msg": "[Безопасность браузера] Настройка Content-Security-Policy: Ожидалось один из: Content-Security-Policy",
        "id": "NGPIX_0007"
    }
}

violation_NGPIX_0008[result] {
    not input.config.add_header in ["Referrer-Policy same-origin"]
    result := {
        "msg": "[Безопасность браузера] Настройка Referrer-Policy same-origin: Ожидалось один из: Referrer-Policy same-origin",
        "id": "NGPIX_0008"
    }
}
