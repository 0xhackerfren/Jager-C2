"""Canonical Jager-C2 task type IDs aligned with teamserver/proto/tasks.proto and implant/include/config.h."""

from __future__ import annotations

from enum import IntEnum


class TaskType(IntEnum):
    TASK_UNKNOWN = 0

    TASK_SLEEP = 1
    TASK_EXIT = 2
    TASK_SELF_DELETE = 3

    TASK_SHELL = 10
    TASK_POWERSHELL = 11
    TASK_EXECUTE = 12
    TASK_EXECUTE_ASSEMBLY = 13
    TASK_BOF = 14
    TASK_SHELLCODE = 15
    TASK_INLINE_EXECUTE = 16

    TASK_LS = 20
    TASK_CD = 21
    TASK_PWD = 22
    TASK_CAT = 23
    TASK_UPLOAD = 24
    TASK_DOWNLOAD = 25
    TASK_RM = 26
    TASK_MKDIR = 27
    TASK_CP = 28
    TASK_MV = 29
    TASK_TIMESTOMP = 30

    TASK_PS = 40
    TASK_KILL_PROCESS = 41
    TASK_SPAWN = 42
    TASK_INJECT = 43
    TASK_MIGRATE = 44

    TASK_IFCONFIG = 50
    TASK_NETSTAT = 51
    TASK_PORTSCAN = 52
    TASK_SOCKS_START = 53
    TASK_SOCKS_STOP = 54
    TASK_PORTFWD_ADD = 55
    TASK_PORTFWD_RM = 56

    TASK_TOKEN_STEAL = 60
    TASK_MAKE_TOKEN = 61
    TASK_REVERT_TOKEN = 62
    TASK_HASHDUMP = 63
    TASK_KERBEROS_TICKETS = 64
    TASK_DPAPI = 65
    TASK_LOGON_USER = 66

    TASK_SLEEP_MASK = 70
    TASK_UNHOOK = 71
    TASK_PATCH_ETW = 72
    TASK_PATCH_AMSI = 73
    TASK_MODULE_STOMP = 74

    TASK_LATERAL_PSEXEC = 80
    TASK_LATERAL_WMI = 81
    TASK_LATERAL_DCOM = 82
    TASK_LATERAL_WINRM = 83
    TASK_LATERAL_SCHTASK = 84

    TASK_PERSIST_REGISTRY = 90
    TASK_PERSIST_SERVICE = 91
    TASK_PERSIST_SCHTASK = 92
    TASK_PERSIST_COM = 93
    TASK_PERSIST_DLL_SIDELOAD = 94

    TASK_SCREENSHOT = 100
    TASK_KEYLOG_START = 101
    TASK_KEYLOG_STOP = 102
    TASK_CLIPBOARD = 103
    TASK_BROWSER_CREDS = 104

    TASK_P2P_LISTEN = 110
    TASK_P2P_CONNECT = 111
    TASK_P2P_RELAY = 112


# Legacy string aliases used by monolithic server.py (mapped to proto values)
LEGACY_TYPE_MAP: dict[str, int] = {
    "shell": TaskType.TASK_SHELL,
    "powershell": TaskType.TASK_POWERSHELL,
    "upload": TaskType.TASK_UPLOAD,
    "download": TaskType.TASK_DOWNLOAD,
    "execute_assembly": TaskType.TASK_EXECUTE_ASSEMBLY,
    "bof": TaskType.TASK_BOF,
    "inject": TaskType.TASK_INJECT,
    "sleep": TaskType.TASK_SLEEP,
    "exit": TaskType.TASK_EXIT,
    "ls": TaskType.TASK_LS,
    "cd": TaskType.TASK_CD,
    "pwd": TaskType.TASK_PWD,
    "cat": TaskType.TASK_CAT,
    "rm": TaskType.TASK_RM,
    "ps": TaskType.TASK_PS,
    "kill": TaskType.TASK_KILL_PROCESS,
    "ifconfig": TaskType.TASK_IFCONFIG,
    "netstat": TaskType.TASK_NETSTAT,
    "portscan": TaskType.TASK_PORTSCAN,
    "screenshot": TaskType.TASK_SCREENSHOT,
}


def resolve_task_type(name: str | int) -> int:
    if isinstance(name, int):
        return name
    key = name.strip().lower()
    if key in LEGACY_TYPE_MAP:
        return int(LEGACY_TYPE_MAP[key])
    if key.startswith("task_"):
        try:
            return int(TaskType[key.upper()])
        except KeyError:
            pass
    raise ValueError(f"Unknown task type: {name}")
