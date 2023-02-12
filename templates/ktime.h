#ifndef __KTIME_H
#define __KTIME_H

#define MAX_CPU_NUMBER 128

struct event {
  int cpu_id;
  uint64_t ts;
};

#endif
