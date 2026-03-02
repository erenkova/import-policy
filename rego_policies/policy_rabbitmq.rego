package main

# Nginx Security Policy
# Generated from Excel
# Compatible with Conftest v0.40+ / OPA v0.60+


violation_RMQ_0001[result] {
    not input.config.auth_mechanisms in ["ANONYMOUS"]
    result := {
        "msg": "[Аутентификация] Запрет анонимной аутентификации: Ожидалось один из: ANONYMOUS",
        "id": "RMQ_0001"
    }
}

violation_RMQ_0001b[result] {
    input.config.loopback_users != "none"
    result := {
        "msg": "[Аутентификация] Настройка loopback_users: Ожидалось none",
        "id": "RMQ_0001b"
    }
}

violation_RMQ_0002[result] {
    not input.config.auth_backends in ["ldap", "internal", "oauth2"]
    result := {
        "msg": "[Аутентификация] Настройка метода аутентификации LDAP: Ожидалось один из: ldap, internal, oauth2",
        "id": "RMQ_0002"
    }
}

violation_RMQ_0002b[result] {
    input.config.auth_ldap.ssl_options.verify != "verify_peer"
    result := {
        "msg": "[Аутентификация] Настройка LDAP SSL verification: Ожидалось verify_peer",
        "id": "RMQ_0002b"
    }
}

violation_RMQ_0002c[result] {
    input.config.auth_mechanisms != "EXTERNAL"
    result := {
        "msg": "[Аутентификация] Настройка метода аутентификации SSL/TLS: Ожидалось EXTERNAL",
        "id": "RMQ_0002c"
    }
}

violation_RMQ_0002d[result] {
    input.config.ssl_options.verify != "verify_peer"
    result := {
        "msg": "[Аутентификация] Настройка SSL peer verification: Ожидалось verify_peer",
        "id": "RMQ_0002d"
    }
}

violation_RMQ_0002e[result] {
    input.config.ssl_options.fail_if_no_peer_cert != true
    result := {
        "msg": "[Аутентификация] Настройка fail_if_no_peer_cert: Ожидалось True",
        "id": "RMQ_0002e"
    }
}

violation_RMQ_0002f[result] {
    input.config.auth_backends != "oauth2"
    result := {
        "msg": "[Аутентификация] Настройка метода аутентификации OAuth2: Ожидалось oauth2",
        "id": "RMQ_0002f"
    }
}

violation_RMQ_0002g[result] {
    input.config.auth_oauth2.https.peer_verification != "verify_peer"
    result := {
        "msg": "[Аутентификация] Настройка OAuth2 peer verification: Ожидалось verify_peer",
        "id": "RMQ_0002g"
    }
}

violation_RMQ_0003[result] {
    input.config.listeners.tcp != "none"
    result := {
        "msg": "[Сеть] Отключение прослушивания TCP-соединений: Ожидалось none",
        "id": "RMQ_0003"
    }
}

violation_RMQ_0004[result] {
    input.config.listeners.ssl.1 != 5671
    result := {
        "msg": "[Сеть] Включение прослушивания SSL-соединений: Ожидалось 5671",
        "id": "RMQ_0004"
    }
}

violation_RMQ_0005[result] {
    input.config.ssl_options.cacertfile != null
    result := {
        "msg": "[Шифрование] Настройка пути к файлу CA сертификата: Ожидалось nan",
        "id": "RMQ_0005"
    }
}

violation_RMQ_0005b[result] {
    input.files["/etc/rabbitmq/certs/*.pem"].permissions != 644.0
    result := {
        "msg": "[Шифрование] Права на файл CA сертификата: Файл /etc/rabbitmq/certs/*.pem должен иметь права 644.0",
        "id": "RMQ_0005b"
    }
}

violation_RMQ_0006[result] {
    input.config.ssl_options.certfile != null
    result := {
        "msg": "[Шифрование] Настройка пути к файлу серверного сертификата: Ожидалось nan",
        "id": "RMQ_0006"
    }
}

violation_RMQ_0006b[result] {
    input.files["/etc/rabbitmq/certs/*.pem"].permissions != 644.0
    result := {
        "msg": "[Шифрование] Права на файл серверного сертификата: Файл /etc/rabbitmq/certs/*.pem должен иметь права 644.0",
        "id": "RMQ_0006b"
    }
}

violation_RMQ_0007[result] {
    input.config.ssl_options.keyfile != null
    result := {
        "msg": "[Шифрование] Настройка пути к файлу приватного ключа: Ожидалось nan",
        "id": "RMQ_0007"
    }
}

violation_RMQ_0007b[result] {
    input.files["/etc/rabbitmq/certs/*.key"].permissions != 400.0
    result := {
        "msg": "[Шифрование] Права на файл приватного ключа: Файл /etc/rabbitmq/certs/*.key должен иметь права 400.0",
        "id": "RMQ_0007b"
    }
}

violation_RMQ_0008[result] {
    not input.config.ssl_options.versions.1 in ["tlsv1.2", "tlsv1.3"]
    result := {
        "msg": "[Шифрование] Настройка версий TLS/SSL: Ожидалось один из: tlsv1.2, tlsv1.3",
        "id": "RMQ_0008"
    }
}

violation_RMQ_0008b[result] {
    input.config.ssl_options.versions.2 != "tlsv1.2"
    result := {
        "msg": "[Шифрование] Настройка версий TLS/SSL (v1.2): Ожидалось tlsv1.2",
        "id": "RMQ_0008b"
    }
}
