package main

# Nginx Security Policy
# Generated from Excel
# Compatible with Conftest v0.40+ / OPA v0.60+


violation_MongoDB_0001[result] {
    not input.config.security.authenticationMechanisms in ["GSSAPI"]
    result := {
        "msg": "[Аутентификация] Настройка Kerberos аутентификации: Ожидалось один из: GSSAPI",
        "id": "MongoDB_0001"
    }
}

violation_MongoDB_0002[result] {
    input.config.security.enableLocalhostAuthBypass != false
    result := {
        "msg": "[Аутентификация] Отключение обхода аутентификации localhost: Ожидалось False",
        "id": "MongoDB_0002"
    }
}

violation_MongoDB_0003[result] {
    not input.config.net.tls.clusterAuthMode in ["x509"]
    result := {
        "msg": "[Аутентификация] Настройка аутентификации в кластере с x.509: Ожидалось один из: x509",
        "id": "MongoDB_0003"
    }
}

violation_MongoDB_0004[result] {
    input.config.net.tls.clusterFile != null
    result := {
        "msg": "[Аутентификация] Настройка файла сертификата кластера: Ожидалось nan",
        "id": "MongoDB_0004"
    }
}

violation_MongoDB_0005[result] {
    not input.config.net.tls.disabledProtocols in ["TLS1_0", "TLS1_1"]
    result := {
        "msg": "[Шифрование] Отключение устаревших протоколов TLS: Ожидалось один из: TLS1_0, TLS1_1",
        "id": "MongoDB_0005"
    }
}

violation_MongoDB_0006[result] {
    not input.config.net.tls.mode in ["requireTLS"]
    result := {
        "msg": "[Шифрование] Включение обязательного TLS режима: Ожидалось один из: requireTLS",
        "id": "MongoDB_0006"
    }
}

violation_MongoDB_0007[result] {
    input.config.net.tls.certificateKeyFile != "/etc/ssl/mongodb.pem"
    result := {
        "msg": "[Шифрование] Настройка файла сертификата TLS: Ожидалось /etc/ssl/mongodb.pem",
        "id": "MongoDB_0007"
    }
}

violation_MongoDB_0008[result] {
    input.config.net.tls.CAFile != "/etc/ssl/caToValidateClientCertificates.pem"
    result := {
        "msg": "[Шифрование] Настройка файла CA для валидации клиентов: Ожидалось /etc/ssl/caToValidateClientCertificates.pem",
        "id": "MongoDB_0008"
    }
}

violation_MongoDB_0009[result] {
    input.files["/etc/ssl/mongodb.pem"].permissions != 400.0
    result := {
        "msg": "[Шифрование] Права на файл сертификата MongoDB: Файл /etc/ssl/mongodb.pem должен иметь права 400.0",
        "id": "MongoDB_0009"
    }
}

violation_MongoDB_0010[result] {
    input.files["/etc/ssl/caToValidateClientCertificates.pem"].permissions != 644.0
    result := {
        "msg": "[Шифрование] Права на файл CA сертификата: Файл /etc/ssl/caToValidateClientCertificates.pem должен иметь права 644.0",
        "id": "MongoDB_0010"
    }
}

violation_MongoDB_0011[result] {
    not input.config.auditLog.destination in ["syslog"]
    result := {
        "msg": "[Логирование] Включение ведения журнала аудита: Ожидалось один из: syslog",
        "id": "MongoDB_0011"
    }
}

violation_MongoDB_0012[result] {
    input.config.systemLog.quiet != false
    result := {
        "msg": "[Логирование] Настройка тихого режима логов: Ожидалось False",
        "id": "MongoDB_0012"
    }
}

violation_MongoDB_0013[result] {
    input.config.systemLog.logAppend != true
    result := {
        "msg": "[Логирование] Настройка добавления записей в конец журнала: Ожидалось True",
        "id": "MongoDB_0013"
    }
}

violation_MongoDB_0014[result] {
    input.config.net.port != null
    result := {
        "msg": "[Сеть] Настройка нестандартного порта MongoDB: Ожидалось nan",
        "id": "MongoDB_0014"
    }
}

violation_MongoDB_0015[result] {
    input.config.net.bindIp != null
    result := {
        "msg": "[Сеть] Настройка привязки к конкретному IP: Ожидалось nan",
        "id": "MongoDB_0015"
    }
}

violation_MongoDB_0016[result] {
    input.config.security.javascriptEnabled != false
    result := {
        "msg": "[Разграничение доступа] Отключение выполнения JavaScript на сервере: Ожидалось False",
        "id": "MongoDB_0016"
    }
}
