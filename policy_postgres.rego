package main

# Nginx Security Policy
# Generated from Excel
# Compatible with Conftest v0.40+ / OPA v0.60+


violation_PG_0001[result] {
    input.config.local != "peer"
    result := {
        "msg": "[Аутентификация] Настройка входа через UNIX Domain Socket для локальных подключений: Ожидалось peer",
        "id": "PG_0001"
    }
}

violation_PG_0002[result] {
    not input.config.hostssl in ["gss", "ldap", "cert", "scram-sha-256"]
    result := {
        "msg": "[Аутентификация] Настройка метода аутентификации gss (Kerberos): Ожидалось один из: gss, ldap, cert, scram-sha-256",
        "id": "PG_0002"
    }
}

violation_PG_0003[result] {
    not input.config.method in ["trust"]
    result := {
        "msg": "[Аутентификация] Запрет метода аутентификации trust: Ожидалось один из: trust",
        "id": "PG_0003"
    }
}

violation_PG_0004[result] {
    not input.config.method in ["password"]
    result := {
        "msg": "[Аутентификация] Запрет метода аутентификации password: Ожидалось один из: password",
        "id": "PG_0004"
    }
}

violation_PG_0005[result] {
    not input.config.method in ["ident"]
    result := {
        "msg": "[Аутентификация] Запрет метода аутентификации ident: Ожидалось один из: ident",
        "id": "PG_0005"
    }
}

violation_PG_0006[result] {
    not input.config.method in ["pam"]
    result := {
        "msg": "[Аутентификация] Запрет метода аутентификации pam: Ожидалось один из: pam",
        "id": "PG_0006"
    }
}

violation_PG_0007[result] {
    not input.config.method in ["bsd"]
    result := {
        "msg": "[Аутентификация] Запрет метода аутентификации bsd: Ожидалось один из: bsd",
        "id": "PG_0007"
    }
}

violation_PG_0008[result] {
    input.files["/etc/postgresql/*/pg_hba.conf"].permissions != 600.0
    result := {
        "msg": "[Файловая система] Права на файл pg_hba.conf: Файл /etc/postgresql/*/pg_hba.conf должен иметь права 600.0",
        "id": "PG_0008"
    }
}

violation_PG_0009[result] {
    input.files["/etc/postgresql/*/postgresql.conf"].permissions != 600.0
    result := {
        "msg": "[Файловая система] Права на файл postgresql.conf: Файл /etc/postgresql/*/postgresql.conf должен иметь права 600.0",
        "id": "PG_0009"
    }
}

violation_PG_0010[result] {
    input.files["/etc/postgresql/*/pg_ident.conf"].permissions != 600.0
    result := {
        "msg": "[Файловая система] Права на файл pg_ident.conf: Файл /etc/postgresql/*/pg_ident.conf должен иметь права 600.0",
        "id": "PG_0010"
    }
}

violation_PG_0011[result] {
    input.files["/var/log/postgresql/*.log"].permissions != 640.0
    result := {
        "msg": "[Файловая система] Права на файлы журналов (log_file_mode): Файл /var/log/postgresql/*.log должен иметь права 640.0",
        "id": "PG_0011"
    }
}

violation_PG_0012[result] {
    input.files["/var/lib/postgresql/*/main"].permissions != 700.0
    result := {
        "msg": "[Файловая система] Права на каталог с данными PGDATA: Файл /var/lib/postgresql/*/main должен иметь права 700.0",
        "id": "PG_0012"
    }
}

violation_PG_0013[result] {
    input.files["/usr/lib/postgresql/*/bin"].permissions != 755.0
    result := {
        "msg": "[Файловая система] Права на каталог с исполняемыми файлами: Файл /usr/lib/postgresql/*/bin должен иметь права 755.0",
        "id": "PG_0013"
    }
}

violation_PG_0014[result] {
    input.config.ssl != "on"
    result := {
        "msg": "[Шифрование] Включение SSL: Ожидалось on",
        "id": "PG_0014"
    }
}

violation_PG_0015[result] {
    input.files["/etc/postgresql//certs/.crt"].permissions != 644.0
    result := {
        "msg": "[Шифрование] Права на файлы SSL сертификатов: Файл /etc/postgresql//certs/.crt должен иметь права 644.0",
        "id": "PG_0015"
    }
}

violation_PG_0015b[result] {
    input.files["/etc/postgresql//certs/.key"].permissions != 600.0
    result := {
        "msg": "[Шифрование] Права на файл SSL ключа: Файл /etc/postgresql//certs/.key должен иметь права 600.0",
        "id": "PG_0015b"
    }
}

violation_PG_0015c[result] {
    input.files["/etc/postgresql//certs/.crt"].permissions != 644.0
    result := {
        "msg": "[Шифрование] Права на файл SSL CA: Файл /etc/postgresql//certs/.crt должен иметь права 644.0",
        "id": "PG_0015c"
    }
}

violation_PG_0016[result] {
    input.config.log_directory != "/var/log/postgresql"
    result := {
        "msg": "[Логирование] Настройка каталога хранения журнала отдельно от PGDATA: Ожидалось /var/log/postgresql",
        "id": "PG_0016"
    }
}

violation_PG_0017[result] {
    input.config.log_truncate_on_rotation != "on"
    result := {
        "msg": "[Логирование] Включение параметра log_truncate_on_rotation: Ожидалось on",
        "id": "PG_0017"
    }
}

violation_PG_0018[result] {
    input.config.log_rotation_age != "1d"
    result := {
        "msg": "[Логирование] Настройка срока жизни файла журнала (log_rotation_age): Ожидалось 1d",
        "id": "PG_0018"
    }
}

violation_PG_0019[result] {
    input.config.log_rotation_size != null
    result := {
        "msg": "[Логирование] Настройка размера файла журнала (log_rotation_size): Ожидалось nan",
        "id": "PG_0019"
    }
}

violation_PG_0020[result] {
    input.config.syslog_sequence_numbers != "on"
    result := {
        "msg": "[Логирование] Включение параметра syslog_sequence_numbers: Ожидалось on",
        "id": "PG_0020"
    }
}

violation_PG_0021[result] {
    input.config.syslog_ident != "postgres"
    result := {
        "msg": "[Логирование] Настройка имени syslog для идентификации логов: Ожидалось postgres",
        "id": "PG_0021"
    }
}

violation_PG_0022[result] {
    input.config.log_min_messages != "warning"
    result := {
        "msg": "[Логирование] Настройка уровня детализации log_min_messages: Ожидалось warning",
        "id": "PG_0022"
    }
}

violation_PG_0023[result] {
    input.config.log_min_error_statement != "error"
    result := {
        "msg": "[Логирование] Настройка уровня детализации log_min_error_statement: Ожидалось error",
        "id": "PG_0023"
    }
}

violation_PG_0024[result] {
    input.config.debug_print_parse != "off"
    result := {
        "msg": "[Логирование] Отключение параметра debug_print_parse: Ожидалось off",
        "id": "PG_0024"
    }
}

violation_PG_0025[result] {
    input.config.debug_print_rewritten != "off"
    result := {
        "msg": "[Логирование] Отключение параметра debug_print_rewritten: Ожидалось off",
        "id": "PG_0025"
    }
}

violation_PG_0026[result] {
    input.config.debug_print_plan != "off"
    result := {
        "msg": "[Логирование] Отключение параметра debug_print_plan: Ожидалось off",
        "id": "PG_0026"
    }
}

violation_PG_0027[result] {
    input.config.debug_pretty_print != "off"
    result := {
        "msg": "[Логирование] Отключение параметра debug_pretty_print: Ожидалось off",
        "id": "PG_0027"
    }
}

violation_PG_0028[result] {
    not input.config.log_statement in ["ddl", "mod", "all"]
    result := {
        "msg": "[Логирование] Настройка параметра log_statement: Ожидалось один из: ddl, mod, all",
        "id": "PG_0028"
    }
}

violation_PG_0029[result] {
    input.config.log_timezone != "localtime"
    result := {
        "msg": "[Логирование] Настройка параметра log_timezone: Ожидалось localtime",
        "id": "PG_0029"
    }
}

violation_PG_0030[result] {
    input.config.logging_collector != "on"
    result := {
        "msg": "[Логирование] Включение logging_collector: Ожидалось on",
        "id": "PG_0030"
    }
}

violation_PG_0031[result] {
    input.config.log_connections != "on"
    result := {
        "msg": "[Логирование] Включение log_connections: Ожидалось on",
        "id": "PG_0031"
    }
}

violation_PG_0032[result] {
    input.config.log_disconnections != "on"
    result := {
        "msg": "[Логирование] Включение log_disconnections: Ожидалось on",
        "id": "PG_0032"
    }
}

violation_PG_0033[result] {
    input.config.log_hostname != "off"
    result := {
        "msg": "[Логирование] Отключение log_hostname: Ожидалось off",
        "id": "PG_0033"
    }
}

violation_PG_0034[result] {
    input.config.log_line_prefix != "%m [%p]: [%l-1] db=%d,user=%u,app=%a,client=%h,state=%e"
    result := {
        "msg": "[Логирование] Настройка log_line_prefix: Ожидалось %m [%p]: [%l-1] db=%d,user=%u,app=%a,client=%h,state=%e",
        "id": "PG_0034"
    }
}

violation_PG_0035[result] {
    input.config.shared_preload_libraries != "passwordcheck"
    result := {
        "msg": "[Аутентификация] Подключение модуля passwordcheck: Ожидалось passwordcheck",
        "id": "PG_0035"
    }
}

violation_PG_0036[result] {
    input.config.shared_preload_libraries != "pgcrypto"
    result := {
        "msg": "[Шифрование] Настройка расширения pgcrypto: Ожидалось pgcrypto",
        "id": "PG_0036"
    }
}

violation_PG_0037[result] {
    input.config.log_replication_commands != "on"
    result := {
        "msg": "[Репликация] Включение log_replication_commands: Ожидалось on",
        "id": "PG_0037"
    }
}

violation_PG_0038[result] {
    not input.config.log_error_verbosity in ["DEFAULT", "VERBOSE", "TERSE"]
    result := {
        "msg": "[Логирование] Настройка log_error_verbosity: Ожидалось один из: DEFAULT, VERBOSE, TERSE",
        "id": "PG_0038"
    }
}
