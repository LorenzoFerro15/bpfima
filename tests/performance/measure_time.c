// Script to measure the time to execute a process
// It substitutes date +%s%N; ... ; date +%s%N to reduce the overhead
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }

    struct timespec start, end;
    pid_t pid;
    int status;

    // Capture start time
    clock_gettime(CLOCK_REALTIME, &start);

    // Fork and execute the target program
    pid = fork();
    if (pid < 0) {
        perror("fork failed");
        return 1;
    } else if (pid == 0) {
        execvp(argv[1], &argv[1]);

        // If execvp fails, exit immediately
        perror("execvp failed");
        exit(1);
    } else {
        // Parent process: wait for the child to finish
        waitpid(pid, &status, 0);
    }

    // Capture precise end time
    clock_gettime(CLOCK_REALTIME, &end);

    // Convert to nanoseconds since epoch
    unsigned long long start_ns = (unsigned long long)start.tv_sec * 1000000000ULL + start.tv_nsec;
    unsigned long long end_ns   = (unsigned long long)end.tv_sec * 1000000000ULL + end.tv_nsec;

    // Print the CSV formatted output
    printf("%llu,%llu,%llu\n", start_ns, end_ns, end_ns-start_ns);

    return 0;
}