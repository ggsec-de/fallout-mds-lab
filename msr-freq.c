/*
 * msr-freq: sample APERF/MPERF on one CPU through /dev/cpu/<n>/msr.
 * Usage: msr-freq <cpu> [interval_ms] [count] [nominal_mhz]
 * Defaults: interval 1 ms, count 2000 (2 s), nominal 3700 MHz (i3-6100).
 * Needs root (or read access to the msr node). Prints one line per sample:
 *   t_ms d_aperf d_mperf approx_mhz
 * approx_mhz = d_aperf / d_mperf * nominal (APERF core cycles vs MPERF
 * base-clock ticks; for this part nominal == max, 3.7 GHz).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MSR_MPERF 0xe7
#define MSR_APERF 0xe8

static int read_msr(int fd, unsigned off, unsigned long long *v)
{
    return pread(fd, v, sizeof(*v), off) == (ssize_t)sizeof(*v) ? 0 : -1;
}

static void sleep_ms(double ms)
{
    struct timespec ts;

    ts.tv_sec = (time_t)(ms / 1000.0);
    ts.tv_nsec = (long)((ms - (double)ts.tv_sec * 1000.0) * 1e6);
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR)
        ;
}

int main(int argc, char **argv)
{
    int cpu = 1, count = 2000, i, fd;
    double interval = 1.0, nominal = 3700.0;
    unsigned long long pa, pm, ca, cm;
    char path[64];

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc > 1)
        cpu = atoi(argv[1]);
    if (argc > 2)
        interval = atof(argv[2]);
    if (argc > 3)
        count = atoi(argv[3]);
    if (argc > 4)
        nominal = atof(argv[4]);

    snprintf(path, sizeof(path), "/dev/cpu/%d/msr", cpu);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
        return 2;
    }
    if (read_msr(fd, MSR_APERF, &pa) || read_msr(fd, MSR_MPERF, &pm)) {
        fprintf(stderr, "pread: %s\n", strerror(errno));
        return 2;
    }
    printf("msr-freq: cpu=%d interval_ms=%.3f nominal_mhz=%.0f\n",
           cpu, interval, nominal);
    for (i = 0; i < count; i++) {
        double t, mhz;
        unsigned long long da, dm;

        sleep_ms(interval);
        if (read_msr(fd, MSR_APERF, &ca) || read_msr(fd, MSR_MPERF, &cm)) {
            fprintf(stderr, "pread: %s\n", strerror(errno));
            return 2;
        }
        t = (double)(i + 1) * interval;
        da = ca - pa;
        dm = cm - pm;
        mhz = dm ? (double)da / (double)dm * nominal : 0.0;
        printf("%.1f %llu %llu %.0f\n", t, da, dm, mhz);
        pa = ca;
        pm = cm;
    }
    close(fd);
    return 0;
}
