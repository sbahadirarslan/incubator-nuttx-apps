/****************************************************************************
 * system/nshlib/nsh_trace.c
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <libgen.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sched.h>
#include <time.h>
#include <nuttx/clock.h>

#if defined(CONFIG_SCHED_INSTRUMENTATION_TRACER) && defined(CONFIG_DRIVER_TRACER)
#  include <nuttx/sched_tracer.h>
#endif

#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL
#  ifdef CONFIG_LIB_SYSCALL
#    include <syscall.h>
#  else
#    define CONFIG_LIB_SYSCALL
#    include <syscall.h>
#    undef CONFIG_LIB_SYSCALL
#  endif
#endif

#ifdef CONFIG_SMP
#  define NCPUS CONFIG_SMP_NCPUS
#else
#  define NCPUS 1
#endif

#include "nsh.h"
#include "nsh_console.h"

#if defined(CONFIG_SCHED_INSTRUMENTATION_TRACER) && defined(CONFIG_DRIVER_TRACER)
#  ifndef CONFIG_NSH_DISABLE_TRACE

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/* Renumber idle task PIDs
 *  In NuttX, PID number less than NCPUS are idle tasks.
 *  In Linux, there is only one idle task of PID 0.
 */

#define get_pid(pid)  ((pid) < NCPUS ? 0 : (pid))

#define get_task_state(s) ((s) <= LAST_READY_TO_RUN_STATE ? 'R' : 'S')

/****************************************************************************
 * Private Types
 ****************************************************************************/

/* The structure to hold the context data of trace dump */

struct trace_dump_context_s
{
  bool ininterrupt;       /* In interrupt handler flag */
  bool pendingswitch;     /* sched_switch pending flag */
  int current_state;      /* Task state of the current line */
  pid_t current_pid;      /* Task PID of the current line */
  pid_t next_pid;         /* Task PID of the next line */
#if CONFIG_TASK_NAME_SIZE > 0
  char current_task_name[CONFIG_TASK_NAME_SIZE + 1];  /* Task name of the current line */
  char next_task_name[CONFIG_TASK_NAME_SIZE + 1];     /* Task name of the next line */
#endif
};

/****************************************************************************
 * Private Data
 ****************************************************************************/

static int g_tracefd;     /* /dev/tracer file descriptor */

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: trace_dump_init_state
 ****************************************************************************/

static void trace_dump_init_context(struct trace_dump_context_s ctx[])
{
  int cpu;

  /* Initialize the trace dump context */

  for (cpu = 0; cpu < NCPUS; cpu++)
    {
      ctx[cpu].ininterrupt = false;
      ctx[cpu].pendingswitch = false;
      ctx[cpu].current_state = TSTATE_TASK_RUNNING;
      ctx[cpu].current_pid = 0;
      ctx[cpu].next_pid = 0;
#if CONFIG_TASK_NAME_SIZE > 0
      strcpy(ctx[cpu].current_task_name, "<noname>");
      strcpy(ctx[cpu].next_task_name, "<noname>");
#endif
    }
}

/****************************************************************************
 * Name: trace_name_coopy
 ****************************************************************************/

#if CONFIG_TASK_NAME_SIZE > 0
static void task_name_copy(FAR char *dst, FAR const char *src)
{
  char c;
  int i;

  /* Copy task name string from src to dst */

  for (i = 0; i < CONFIG_TASK_NAME_SIZE; i++)
    {
      c = *src++;

      if (c == '\0')
        {
          break;
        }
      else if (c == ' ')
        {
          /* Replace space to underline
           * Text trace data format cannot treat a space as a task name.
           */

          c = '_';
        }

      *dst++ = c;
    }

  *dst = '\0';
}
#endif

/****************************************************************************
 * Name: trace_dump_header
 ****************************************************************************/

static void trace_dump_header(FILE *out,
                              struct trace_dump_context_s ctx[],
                              FAR struct tracer_common_s *tc)
{
#ifdef CONFIG_SMP
  int cpu = tc->cpu;
#else
  int cpu = 0;
#endif

  fprintf(out, "%8s-%-3u [%d] %3u.%09u: ",
#if CONFIG_TASK_NAME_SIZE > 0
          ctx[cpu].current_task_name
#else
          "<noname>"
#endif
          , ctx[cpu].current_pid,
          cpu, tc->systime.tv_sec, tc->systime.tv_nsec);
}

/****************************************************************************
 * Name: trace_dump_sched_switch
 ****************************************************************************/

static void trace_dump_sched_switch(FILE *out,
                                    struct trace_dump_context_s ctx[],
                                    FAR struct tracer_common_s *tc)
{
#ifdef CONFIG_SMP
  int cpu = tc->cpu;
#else
  int cpu = 0;
#endif

  fprintf(out, "sched_switch: "
               "prev_comm=%s prev_pid=%u prev_state=%c ==> "
               "next_comm=%s next_pid=%u\n",
#if CONFIG_TASK_NAME_SIZE > 0
          ctx[cpu].current_task_name
#else
          "<noname>"
#endif
          , ctx[cpu].current_pid,
          get_task_state(ctx[cpu].current_state),
#if CONFIG_TASK_NAME_SIZE > 0
          ctx[cpu].next_task_name
#else
          "<noname>"
#endif
          , ctx[cpu].next_pid);
  ctx[cpu].current_pid = ctx[cpu].next_pid;
#if CONFIG_TASK_NAME_SIZE > 0
  task_name_copy(ctx[cpu].current_task_name, ctx[cpu].next_task_name);
#endif
  ctx[cpu].pendingswitch = false;
}

/****************************************************************************
 * Name: trace_dump_one
 ****************************************************************************/

static int trace_dump_one(FILE *out,
                          struct trace_dump_context_s ctx[],
                          FAR uint8_t *p)
{
  FAR struct tracer_common_s *tc = (FAR struct tracer_common_s *)p;
#ifdef CONFIG_SMP
  int cpu = tc->cpu;
#else
  int cpu = 0;
#endif

  /* Output one trace event */

  switch (tc->type)
    {
      case TRACER_FIRST:
        {
          FAR struct tracer_first_s *t = (FAR struct tracer_first_s *)p;

          /* The first event of the trace data
           * It provides the current running task information.
           */

          ctx[cpu].current_pid = get_pid(t->pid);
#if CONFIG_TASK_NAME_SIZE > 0
          task_name_copy(ctx[cpu].current_task_name, t->name);
#endif
          ctx[cpu].current_state = TSTATE_TASK_RUNNING;
        }
        break;

      case TRACER_MESSAGE:
        {
          FAR struct tracer_message_s *t = (FAR struct tracer_message_s *)p;

          trace_dump_header(out, ctx, tc);
          fprintf(out, "trace_message: %s\n", t->message);
        }
        break;

      case TRACER_START:
        {
          FAR struct tracer_start_s *t = (FAR struct tracer_start_s *)p;
#if CONFIG_TASK_NAME_SIZE > 0
          char task_name[CONFIG_TASK_NAME_SIZE + 1];

          task_name_copy(task_name, t->name);
#endif
          trace_dump_header(out, ctx, tc);
          fprintf(out, "sched_wakeup_new: comm=%s pid=%d target_cpu=0\n",
#if CONFIG_TASK_NAME_SIZE > 0
                  task_name
#else
                  "<noname>"
#endif
                  , get_pid(t->pid));
        }
        break;

      case TRACER_STOP:
        {
          FAR struct tracer_stop_s *t = (FAR struct tracer_stop_s *)p;
#if CONFIG_TASK_NAME_SIZE > 0
          char task_name[CONFIG_TASK_NAME_SIZE + 1];

          task_name_copy(task_name, t->name);
#endif
          trace_dump_header(out, ctx, tc);
          fprintf(out, "sched_switch: "
                       "prev_comm=%s prev_pid=%u prev_state=%c ==> "
                       "next_comm=%s next_pid=%u\n",
#if CONFIG_TASK_NAME_SIZE > 0
                  task_name
#else
                  "<noname>"
#endif
                  , get_pid(t->pid), 'X',
#if CONFIG_TASK_NAME_SIZE > 0
                  ctx[cpu].current_task_name
#else
                  "<noname>"
#endif
                  , ctx[cpu].current_pid);
        }
        break;

      case TRACER_SUSPEND:
        {
          FAR struct tracer_suspend_s *t = (FAR struct tracer_suspend_s *)p;

          /* This event informs the task to be suspended.
           * Preserve the information for the succeeding TRACE_RESUME event.
           */

          ctx[cpu].current_pid = get_pid(t->pid);
#if CONFIG_TASK_NAME_SIZE > 0
          task_name_copy(ctx[cpu].current_task_name, t->name);
#endif
          ctx[cpu].current_state = t->state;
        }
        break;

      case TRACER_RESUME:
        {
          FAR struct tracer_resume_s *t = (FAR struct tracer_resume_s *)p;

          /* This event informs the task to be resumed.
           * The task switch timing depends on the running context.
           */

          ctx[cpu].next_pid = get_pid(t->pid);
#if CONFIG_TASK_NAME_SIZE > 0
          task_name_copy(ctx[cpu].next_task_name, t->name);
#endif
          if (!ctx[cpu].ininterrupt)
            {
              /* If not in the interrupt context, the task switch is
               * executed immediately.
               */

              trace_dump_header(out, ctx, tc);
              trace_dump_sched_switch(out, ctx, tc);
            }
          else
            {
              /* If in the interrupt context, the task switch is postponed
               * until leaving the interrupt handler.
               */

              trace_dump_header(out, ctx, tc);
              fprintf(out, "sched_waking: comm=%s pid=%d target_cpu=0\n",
#if CONFIG_TASK_NAME_SIZE > 0
                      ctx[cpu].next_task_name
#else
                      "<noname>"
#endif
                      , ctx[cpu].next_pid);
              ctx[cpu].pendingswitch = true;
            }
        }
        break;

#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL
      case TRACER_SYSCALL_ENTER:
        {
          FAR struct tracer_syscall_enter_s *t;
          int i;

          t = (FAR struct tracer_syscall_enter_s *)p;
          trace_dump_header(out, ctx, tc);
          fprintf(out, "sys_%s(", g_syscallname[t->nr]);

          for (i = 0; i < t->argc; i++)
            {
              if (i == 0)
                {
                  fprintf(out, "arg%d: 0x%x", i, t->argv[i]);
                }
              else
                {
                  fprintf(out, ", arg%d: 0x%x", i, t->argv[i]);
                }
            }

          fprintf(out, ")\n");
        }
        break;

      case TRACER_SYSCALL_LEAVE:
        {
          FAR struct tracer_syscall_leave_s *t;

          t = (FAR struct tracer_syscall_leave_s *)p;
          trace_dump_header(out, ctx, tc);
          fprintf(out, "sys_%s -> 0x%x\n",
                  g_syscallname[t->nr],
                  t->result);
        }
        break;
#endif

#ifdef CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER
      case TRACER_IRQHANDLER_ENTER:
        {
          FAR struct tracer_irqhandler_enter_s *t;

          t = (FAR struct tracer_irqhandler_enter_s *)p;
          trace_dump_header(out, ctx, tc);
          fprintf(out, "irq_handler_entry: irq=%u addr=0x%x\n",
                  t->irq,
                  t->handler);
          ctx[cpu].ininterrupt = true;
        }
        break;

      case TRACER_IRQHANDLER_LEAVE:
        {
          FAR struct tracer_irqhandler_leave_s *t;

          t = (FAR struct tracer_irqhandler_leave_s *)p;
          trace_dump_header(out, ctx, tc);
          fprintf(out, "irq_handler_exit: irq=%u\n",
                  t->irq);
          ctx[cpu].ininterrupt = false;
          if (ctx[cpu].pendingswitch)
            {
              /* If the pending task switch exists, it is executed here */

              trace_dump_header(out, ctx, tc);
              trace_dump_sched_switch(out, ctx, tc);
            }
        }
        break;
#endif

      default:
        break;
    }

  /* Return the length of the processed trace event */

  return tc->length;
}

/****************************************************************************
 * Name: trace_dump
 ****************************************************************************/

static int trace_dump(FILE *out)
{
  struct trace_dump_context_s ctx[NCPUS];
  char tracedata[UCHAR_MAX];
  char *p;
  int size;
  int ret;
  int fd;

  /* Open trace device for read */

  fd = open("/dev/tracer", O_RDONLY);
  if (fd < 0)
    {
      return ERROR;
    }

  trace_dump_init_context(ctx);

  /* Read and output all trace events */

  while (1)
    {
      ret = read(fd, tracedata, sizeof tracedata);
      if (ret <= 0)
        {
          break;
        }

      p = tracedata;
      do
        {
          size = trace_dump_one(out, ctx, (FAR uint8_t *)p);
          p += size;
          ret -= size;
        }
      while (ret > 0);
    }

  /* Close trace device */

  close(fd);

  return ret;
}

/****************************************************************************
 * Name: trace_cmd_start
 ****************************************************************************/

static int trace_cmd_start(FAR struct nsh_vtbl_s *vtbl,
                           int index, int argc, char **argv)
{
  char *endptr;
  int duration = 0;

  /* Usage: trace start [<duration>] */

  if (index < argc - 1)
    {
      index++;
      duration = strtol(argv[index], &endptr, 0);
      if (!duration || endptr == argv[index] || *endptr != '\0')
        {
          nsh_output(vtbl, g_fmtarginvalid, argv[0]);
          return ERROR;
        }
    }

  /* Start tracing */

#ifdef CONFIG_BUILD_FLAT
  sched_tracer_start();
#else
  ioctl(g_tracefd, TRIOC_START, 0);
#endif

  if (duration > 0)
    {
      /* If <duration> is given, stop tracing after specified seconds. */

      sleep(duration);
#ifdef CONFIG_BUILD_FLAT
      sched_tracer_stop();
#else
  ioctl(g_tracefd, TRIOC_STOP, 0);
#endif
    }

  return index;
}

/****************************************************************************
 * Name: trace_cmd_dump
 ****************************************************************************/

static int trace_cmd_dump(FAR struct nsh_vtbl_s *vtbl,
                          int index, int argc, char **argv)
{
  FAR char *fullpath;
  FILE *out = stdout;
  int ret;

  /* Usage: trace dump [<filename>] */

  /* If <filename> is '-' or not given, trace dump is displayed
   * to stdout.
   */

  if (index < argc - 1)
    {
      index++;
      if (strcmp(argv[index], "-") != 0)
        {
          /* If <filename> is given, open the file stream for output. */

          fullpath = nsh_getfullpath(vtbl, argv[index]);
          if (fullpath == NULL)
            {
              nsh_output(vtbl, g_fmtcmdoutofmemory, argv[0]);
              return ERROR;
            }

          out = fopen(fullpath, "w");
          if (out == NULL)
            {
              nsh_output(vtbl, g_fmtcmdfailed, argv[0], "open", NSH_ERRNO);
              return ERROR;
            }

          nsh_freefullpath(fullpath);
        }
    }

  /* Dump the trace data */

  ret = trace_dump(out);

  /* If needed, close the file stream for dump. */

  if (out != stdout)
    {
      fclose(out);
    }

  if (ret < 0)
    {
      nsh_output(vtbl, g_fmtcmdfailed, argv[0], "open", NSH_ERRNO);
      return ERROR;
    }

  return index;
}

/****************************************************************************
 * Name: trace_cmd_cmd
 ****************************************************************************/

static int trace_cmd_cmd(FAR struct nsh_vtbl_s *vtbl,
                         int index, int argc, char **argv)
{
#ifndef CONFIG_NSH_DISABLEBG
  bool bgsave;
#endif
#if CONFIG_NFILE_STREAMS > 0
  bool redirsave;
#endif
  int ret;

  /* Usage: trace cmd "<command>" */

  index++;
  if (index >= argc)
    {
      /* <command> parameter is mandatory. */

      nsh_output(vtbl, g_fmtargrequired, argv[0]);
      return ERROR;
    }

  /* Save state */

#ifndef CONFIG_NSH_DISABLEBG
  bgsave    = vtbl->np.np_bg;
#endif
#if CONFIG_NFILE_STREAMS > 0
  redirsave = vtbl->np.np_redirect;
#endif

  /* Execute the command with tracing */

#ifdef CONFIG_BUILD_FLAT
  sched_tracer_start();
#else
  ioctl(g_tracefd, TRIOC_START, 0);
#endif
  ret = nsh_parse(vtbl, argv[index]);
#ifdef CONFIG_BUILD_FLAT
  sched_tracer_stop();
#else
  ioctl(g_tracefd, TRIOC_STOP, 0);
#endif

  /* Restore state */

#ifndef CONFIG_NSH_DISABLEBG
  vtbl->np.np_bg       = bgsave;
#endif
#if CONFIG_NFILE_STREAMS > 0
  vtbl->np.np_redirect = redirsave;
#endif

  if (ret < 0)
    {
      return ret;
    }

  return index;
}

/****************************************************************************
 * Name: trace_cmd_mode
 ****************************************************************************/

static int trace_cmd_mode(FAR struct nsh_vtbl_s *vtbl,
                          int index, int argc, char **argv)
{
  struct tracer_mode_s mode;
  bool enable;
  bool modified;
#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL
  size_t nsys;
  struct tracer_syscallfilter_s *filter_syscall;
#endif
#ifdef CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER
  size_t nirq;
  struct tracer_irqfilter_s *filter_irq;
#endif

  /* Usage: trace mode [{+|-}{o|s|a|i}...] */

  /* Get current trace mode */

  ioctl(g_tracefd, TRIOC_GETMODE, (unsigned long)&mode);
  modified = false;

  /* Parse the mode setting parameters */

  while (index < argc - 1)
    {
      if (argv[index + 1][0] != '-' && argv[index + 1][0] != '+')
        {
          break;
        }

      index++;
      enable = (argv[index][0] == '+');

      switch (argv[index][1])
        {
          case 'o':
            if (enable)
              {
                mode.flag |= TRIOC_MODE_FLAG_ONESHOT;
              }
            else
              {
                mode.flag &= ~TRIOC_MODE_FLAG_ONESHOT;
              }
            break;

#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL
          case 's':
            if (enable)
              {
                mode.flag |= TRIOC_MODE_FLAG_SYSCALL;
              }
            else
              {
                mode.flag &= ~TRIOC_MODE_FLAG_SYSCALL;
              }
            break;

          case 'a':
            if (enable)
              {
                mode.flag |= TRIOC_MODE_FLAG_SYSCALL_ARGS;
              }
            else
              {
                mode.flag &= ~TRIOC_MODE_FLAG_SYSCALL_ARGS;
              }
            break;
#endif

#ifdef CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER
          case 'i':
            if (enable)
              {
                mode.flag |= TRIOC_MODE_FLAG_IRQ;
              }
            else
              {
                mode.flag &= ~TRIOC_MODE_FLAG_IRQ;
              }
            break;
#endif

          default:
            nsh_output(vtbl, g_fmtsyntax, argv[0]);
            return ERROR;
        }

      /* Update trace mode */

      ioctl(g_tracefd, TRIOC_SETMODE, (unsigned long)&mode);
      modified = true;
    }

  if (modified)
    {
      return index;
    }

  /* If no parameter, display current trace mode setting. */

#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL
  nsys = (size_t)ioctl(g_tracefd, TRIOC_GETSYSCALLFILTER, 0);

  filter_syscall = (struct tracer_syscallfilter_s *)malloc(nsys);
  if (filter_syscall == NULL)
    {
      nsh_output(vtbl, g_fmtcmdoutofmemory, argv[0]);
      return ERROR;
    }

  ioctl(g_tracefd, TRIOC_GETSYSCALLFILTER, (unsigned long)filter_syscall);
#endif

#ifdef CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER
  nirq = (size_t)ioctl(g_tracefd, TRIOC_GETIRQFILTER, 0);

  filter_irq = (struct tracer_irqfilter_s *)malloc(nirq);
  if (filter_irq == NULL)
    {
      nsh_output(vtbl, g_fmtcmdoutofmemory, argv[0]);
#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL
      free(filter_syscall);
#endif
      return ERROR;
    }

  ioctl(g_tracefd, TRIOC_GETIRQFILTER, (unsigned long)filter_irq);
#endif

  nsh_output(vtbl, "Task trace mode:\n");
  nsh_output(vtbl, " Oneshot                 : %s\n",
             mode.flag & TRIOC_MODE_FLAG_ONESHOT ? "on  (+o)" : "off (-o)");

#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL
  nsh_output(vtbl, " Syscall trace           : %s\n",
             mode.flag & TRIOC_MODE_FLAG_SYSCALL ? "on  (+s)" : "off (-s)");
  if (mode.flag & TRIOC_MODE_FLAG_SYSCALL)
    {
      nsh_output(vtbl, "  Filtered Syscalls      : %d\n",
                 filter_syscall->nr_syscalls);
    }

  nsh_output(vtbl, " Syscall trace with args : %s\n",
             mode.flag & TRIOC_MODE_FLAG_SYSCALL_ARGS ?
              "on  (+a)" : "off (-a)");
#endif

#ifdef CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER
  nsh_output(vtbl, " IRQ trace               : %s\n",
             mode.flag & TRIOC_MODE_FLAG_IRQ ? "on  (+i)" : "off (-i)");
  if (mode.flag & TRIOC_MODE_FLAG_IRQ)
    {
      nsh_output(vtbl, "  Filtered IRQs          : %d\n",
                 filter_irq->nr_irqs);
    }
#endif

#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL
  free(filter_syscall);
#endif
#ifdef CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER
  free(filter_irq);
#endif

  return index;
}

/****************************************************************************
 * Name: match_syscall
 ****************************************************************************/

#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL
static int match_syscall(FAR const char *pattern, FAR const char *name)
{
  FAR const char *p = pattern;
  FAR const char *n = name;

  /* Simple wildcard matcher to specify the syscalls to be masked */

  while (1)
    {
      if (*n == '\0')
        {
          if (*p == '*')
            {
              p++;
            }

          return *p == '\0';
        }
      else if (*p == '\0')
        {
          return false;
        }
      else if (*p == '*')
        {
          if (p[1] == '\0')
            {
              return true;
            }
          else if (match_syscall(p, n + 1))
            {
              return true;
            }
          else if (match_syscall(p + 1, n))
            {
              return true;
            }

          return false;
        }
      else if (*p == *n)
        {
          p++;
          n++;
        }
      else
        {
          return false;
        }
    }
}
#endif

/****************************************************************************
 * Name: trace_cmd_syscall
 ****************************************************************************/

#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL
static int trace_cmd_syscall(FAR struct nsh_vtbl_s *vtbl,
                            int index, int argc, char **argv)
{
  struct tracer_mode_s mode;
  bool enable;
  bool modified;
  int syscallno;
  FAR struct tracer_syscallfilter_s *filter_syscall;
  int n;

  /* Usage: trace syscall [{+|-}<syscallname>...] */

  /* Get current syscall filter setting */

  modified = false;
  filter_syscall = (struct tracer_syscallfilter_s *)
                    malloc(sizeof(struct tracer_syscallfilter_s) +
                           sizeof(int) * SYS_nsyscalls);
  if (filter_syscall == NULL)
    {
      nsh_output(vtbl, g_fmtcmdoutofmemory, argv[0]);
      return ERROR;
    }

  ioctl(g_tracefd, TRIOC_GETSYSCALLFILTER, (unsigned long)filter_syscall);

  /* Parse the setting parameters */

  while (index < argc - 1)
    {
      if (argv[index + 1][0] != '-' && argv[index + 1][0] != '+')
        {
          break;
        }

      index++;
      modified = true;
      enable = (argv[index][0] == '+');

      /* Check whether the given pattern matches for each syscall names */

      for (syscallno = 0; g_syscallname[syscallno] != NULL; syscallno++)
        {
          if (!match_syscall(&argv[index][1], g_syscallname[syscallno]))
            {
              continue;
            }

          /* If matches, update the masked syscall number list */

          if (enable)
            {
              for (n = 0; n < filter_syscall->nr_syscalls; n++)
                {
                  if (filter_syscall->syscall[n] == syscallno)
                    {
                      break;
                    }
                }

              if (n >= filter_syscall->nr_syscalls)
                {
                  filter_syscall->syscall[filter_syscall->nr_syscalls] =
                    syscallno;
                  filter_syscall->nr_syscalls++;
                }
            }
          else
            {
              for (n = 0; n < filter_syscall->nr_syscalls; n++)
                {
                  if (filter_syscall->syscall[n] == syscallno)
                    {
                      for (; n < filter_syscall->nr_syscalls - 1; n++)
                        {
                          filter_syscall->syscall[n] =
                            filter_syscall->syscall[n + 1];
                        }

                      filter_syscall->nr_syscalls--;
                    }
                }
            }
        }
    }

  if (modified)
    {
      /* Update current syscall filter setting */

      ioctl(g_tracefd, TRIOC_SETSYSCALLFILTER,
            (unsigned long)filter_syscall);

      /* Enable syscall trace flag */

      ioctl(g_tracefd, TRIOC_GETMODE, (unsigned long)&mode);
      mode.flag |= TRIOC_MODE_FLAG_SYSCALL;
      ioctl(g_tracefd, TRIOC_SETMODE, (unsigned long)&mode);
    }
  else
    {
      /* If no parameter, display current setting. */

      nsh_output(vtbl, "Filtered Syscalls: %d\n",
                 filter_syscall->nr_syscalls);
      for (n = 0; n < filter_syscall->nr_syscalls; n++)
        {
          nsh_output(vtbl, "  %s\n",
                     g_syscallname[filter_syscall->syscall[n]]);
        }
    }

  free(filter_syscall);
  return index;
}
#endif

/****************************************************************************
 * Name: trace_cmd_irq
 ****************************************************************************/

#ifdef CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER
static int trace_cmd_irq(FAR struct nsh_vtbl_s *vtbl,
                         int index, int argc, char **argv)
{
  struct tracer_mode_s mode;
  bool enable;
  bool modified;
  int irqno;
  char *endptr;
  struct tracer_irqfilter_s *filter_irq;
  int n;

  /* Usage: trace irq [{+|-}<irqnum>...] */

  modified = false;
  filter_irq = (struct tracer_irqfilter_s *)
                malloc(sizeof(struct tracer_irqfilter_s)
                       + sizeof(int) * NR_IRQS);
  if (filter_irq == NULL)
    {
      nsh_output(vtbl, g_fmtcmdoutofmemory, argv[0]);
      return ERROR;
    }

  ioctl(g_tracefd, TRIOC_GETIRQFILTER, (unsigned long)filter_irq);

  /* Parse the setting parameters */

  while (index < argc - 1)
    {
      if (argv[index + 1][0] != '-' && argv[index + 1][0] != '+')
        {
          break;
        }

      index++;
      modified = true;
      enable = (argv[index][0] == '+');

      if (argv[index][1] == '*')
        {
          /* Mask or unmask all IRQs */

          if (enable)
            {
              filter_irq->nr_irqs = NR_IRQS;
              for (n = 0; n < NR_IRQS; n++)
                {
                  filter_irq->irq[n] = n;
                }
            }
          else
            {
              filter_irq->nr_irqs = 0;
            }

          continue;
        }

      /* Get IRQ number */

      irqno = strtol(&argv[index][1], &endptr, 0);
      if (endptr == argv[index] || *endptr != '\0')
        {
          nsh_output(vtbl, g_fmtarginvalid, argv[0]);
          return ERROR;
        }

      /* Update the masked IRQ number list */

      if (enable)
        {
          for (n = 0; n < filter_irq->nr_irqs; n++)
            {
              if (filter_irq->irq[n] == irqno)
                {
                  break;
                }
            }

          if (n >= filter_irq->nr_irqs)
            {
              filter_irq->irq[filter_irq->nr_irqs] = irqno;
              filter_irq->nr_irqs++;
            }
        }
      else
        {
          for (n = 0; n < filter_irq->nr_irqs; n++)
            {
              if (filter_irq->irq[n] == irqno)
                {
                  for (; n < filter_irq->nr_irqs - 1; n++)
                    {
                      filter_irq->irq[n] = filter_irq->irq[n + 1];
                    }

                  filter_irq->nr_irqs--;
                }
            }
        }
    }

  if (modified)
    {
      /* Update current irq filter setting */

      ioctl(g_tracefd, TRIOC_SETIRQFILTER, (unsigned long)filter_irq);

      /* Enable irq trace flag */

      ioctl(g_tracefd, TRIOC_GETMODE, (unsigned long)&mode);
      mode.flag |= TRIOC_MODE_FLAG_IRQ;
      ioctl(g_tracefd, TRIOC_SETMODE, (unsigned long)&mode);
    }
  else
    {
      /* If no parameter, display current setting. */

      nsh_output(vtbl, "Filtered IRQs: %d\n", filter_irq->nr_irqs);
      for (n = 0; n < filter_irq->nr_irqs; n++)
        {
          nsh_output(vtbl, "  %d\n", filter_irq->irq[n]);
        }
    }

  free(filter_irq);
  return index;
}
#endif

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: cmd_trace
 ****************************************************************************/

int cmd_trace(FAR struct nsh_vtbl_s *vtbl, int argc, char **argv)
{
  int ret = OK;
  int i;

  /* Open trace device for control */

  g_tracefd = open("/dev/tracer", O_WRONLY);
  if (g_tracefd < 0)
    {
      nsh_output(vtbl, g_fmtcmdfailed, argv[0], "open", NSH_ERRNO);
      return ERROR;
    }

  if (argc == 1)
    {
      /* No arguments - dump the trace data */

      trace_dump(stdout);
    }

  /* Parse command line arguments */

  for (i = 1; i < argc; i++)
    {
      if (strcmp(argv[i], "start") == 0)
        {
          i = trace_cmd_start(vtbl, i, argc, argv);
        }
      else if (strcmp(argv[i], "stop") == 0)
        {
#ifdef CONFIG_BUILD_FLAT
          sched_tracer_stop();
#else
          ioctl(g_tracefd, TRIOC_STOP, 0);
#endif
        }
      else if (strcmp(argv[i], "dump") == 0)
        {
          i = trace_cmd_dump(vtbl, i, argc, argv);
        }
      else if (strcmp(argv[i], "cmd") == 0)
        {
          i = trace_cmd_cmd(vtbl, i, argc, argv);
        }
      else if (strcmp(argv[i], "mode") == 0)
        {
          i = trace_cmd_mode(vtbl, i, argc, argv);
        }
#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL
      else if (strcmp(argv[i], "syscall") == 0)
        {
          i = trace_cmd_syscall(vtbl, i, argc, argv);
        }
#endif
#ifdef CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER
      else if (strcmp(argv[i], "irq") == 0)
        {
          i = trace_cmd_irq(vtbl, i, argc, argv);
        }
#endif
      else
        {
          nsh_output(vtbl, g_fmtsyntax, argv[0]);
          ret = ERROR;
          break;
        }

      if (i < 0)
        {
          break;
        }
    }

  /* Close trace device */

  close(g_tracefd);
  return ret;
}

#  endif /* CONFIG_NSH_DISABLE_TRACE */
#endif /* defined(CONFIG_SCHED_INSTRUMENTATION_TRACER) && defined(CONFIG_DRIVER_TRACER) */
