//===- profile.c - batch builds from a profile file -----------------------===//
//
// One invocation, many payloads, deterministic settings. The format is
// deliberately boring: [section] headers and key = value lines, so it parses
// with fgets and no dependency.
//
//   # defaults applied to every job
//   [default]
//   arch   = 2
//   format = bin
//
//   [job]
//   input  = payload.dll
//   method = Run
//   output = out/payload.bin
//
//   [job]
//   input = other.exe
//   output = out/other.bin
//
// Keys mirror the long CLI options. `--output` on the command line, when used
// with a profile, is treated as an output directory: a job with no `output`
// key writes `<dir>/<input basename>.<format>`.

#include "donut.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PROFILE_MAX_JOBS  128
#define PROFILE_LINE_MAX  1024

static char *trim(char *s) {
  char *end;
  while (*s != 0 && isspace((unsigned char)*s)) s++;
  end = s + strlen(s);
  while (end > s && isspace((unsigned char)end[-1])) end--;
  *end = 0;
  return s;
}

static int to_int(const char *s, int fallback) {
  int v;
  if (s == NULL || *s == 0) return fallback;
  v = atoi(s);
  return v != 0 ? v : fallback;
}

// "bin", "base64", ... or 1..9
static int to_format(const char *s) {
  if (s == NULL || *s == 0) return DONUT_FORMAT_BINARY;
  if (isdigit((unsigned char)*s)) return to_int(s, DONUT_FORMAT_BINARY);
  if (!strcasecmp(s, "bin") || !strcasecmp(s, "binary")) return 1;
  if (!strcasecmp(s, "base64")) return 2;
  if (!strcasecmp(s, "c")) return 3;
  if (!strcasecmp(s, "ruby")) return 4;
  if (!strcasecmp(s, "python")) return 5;
  if (!strcasecmp(s, "powershell") || !strcasecmp(s, "ps1")) return 6;
  if (!strcasecmp(s, "csharp") || !strcasecmp(s, "cs")) return 7;
  if (!strcasecmp(s, "hex")) return 8;
  return DONUT_FORMAT_BINARY;
}

static int to_arch(const char *s) {
  if (s == NULL || *s == 0) return DONUT_ARCH_X84;
  if (!strcasecmp(s, "x86")) return DONUT_ARCH_X86;
  if (!strcasecmp(s, "x64") || !strcasecmp(s, "amd64")) return DONUT_ARCH_X64;
  if (!strcasecmp(s, "any") || !strcasecmp(s, "dual")) return DONUT_ARCH_X84;
  return to_int(s, DONUT_ARCH_X84);
}

static int to_exit(const char *s) {
  if (s == NULL || *s == 0) return DONUT_OPT_EXIT_THREAD;
  if (!strcasecmp(s, "thread")) return DONUT_OPT_EXIT_THREAD;
  if (!strcasecmp(s, "process")) return DONUT_OPT_EXIT_PROCESS;
  if (!strcasecmp(s, "block")) return DONUT_OPT_EXIT_BLOCK;
  return to_int(s, DONUT_OPT_EXIT_THREAD);
}

static int to_bool(const char *s, int fallback) {
  if (s == NULL || *s == 0) return fallback;
  if (!strcasecmp(s, "1") || !strcasecmp(s, "yes") || !strcasecmp(s, "true"))
    return 1;
  if (!strcasecmp(s, "0") || !strcasecmp(s, "no") || !strcasecmp(s, "false"))
    return 0;
  return to_int(s, fallback);
}

static void copy_str(char *dst, const char *src, size_t cap) {
  if (src == NULL) return;
  strncpy(dst, src, cap - 1);
  dst[cap - 1] = 0;
}

// Apply one key to one config. Unknown keys are a warning, not a failure:
// a profile written for a newer build should still do what it can.
static int apply_key(DONUT_CONFIG *c, const char *key, const char *val) {
  if (!strcasecmp(key, "input") || !strcasecmp(key, "file")) {
    copy_str(c->input, val, sizeof(c->input));
  } else if (!strcasecmp(key, "output")) {
    copy_str(c->output, val, sizeof(c->output));
  } else if (!strcasecmp(key, "arch") || !strcasecmp(key, "cpu")) {
    c->arch = to_arch(val);
  } else if (!strcasecmp(key, "format")) {
    c->format = to_format(val);
  } else if (!strcasecmp(key, "entropy")) {
    c->entropy = to_int(val, DONUT_ENTROPY_DEFAULT);
  } else if (!strcasecmp(key, "compress")) {
    c->compress = to_int(val, DONUT_COMPRESS_NONE);
  } else if (!strcasecmp(key, "headers")) {
    c->headers = to_int(val, DONUT_HEADERS_OVERWRITE);
  } else if (!strcasecmp(key, "exit")) {
    c->exit_opt = to_exit(val);
  } else if (!strcasecmp(key, "thread")) {
    c->thread = to_bool(val, 0);
  } else if (!strcasecmp(key, "unicode")) {
    c->unicode = to_bool(val, 0);
  } else if (!strcasecmp(key, "pack")) {
    c->pack = to_bool(val, 1);
  } else if (!strcasecmp(key, "no_pack") || !strcasecmp(key, "no-pack")) {
    c->no_pack = to_bool(val, 0);
  } else if (!strcasecmp(key, "type")) {
    c->payload_type = to_int(val, 1);
  } else if (!strcasecmp(key, "method") || !strcasecmp(key, "function")) {
    copy_str(c->method, val, sizeof(c->method));
  } else if (!strcasecmp(key, "args") || !strcasecmp(key, "params")) {
    copy_str(c->args, val, sizeof(c->args));
  } else if (!strcasecmp(key, "unhook")) {
    copy_str(c->unhook, val, sizeof(c->unhook));
  } else {
    printf("  [ profile: unknown key \"%s\" ignored\n", key);
    return 0;
  }
  return 1;
}

static void default_config(DONUT_CONFIG *c) {
  memset(c, 0, sizeof(*c));
  c->inst_type    = DONUT_INSTANCE_EMBED;
  c->payload_type = 1;
  c->arch         = DONUT_ARCH_X84;
  c->headers      = DONUT_HEADERS_OVERWRITE;
  c->format       = DONUT_FORMAT_BINARY;
  c->compress     = DONUT_COMPRESS_NONE;
  c->entropy      = DONUT_ENTROPY_DEFAULT;
  c->exit_opt     = DONUT_OPT_EXIT_THREAD;
  c->pack         = 1;
}

static const char *format_ext(int format) {
  switch (format) {
    case DONUT_FORMAT_BASE64:     return "b64";
    case DONUT_FORMAT_C:          return "c";
    case DONUT_FORMAT_RUBY:       return "rb";
    case DONUT_FORMAT_PYTHON:     return "py";
    case DONUT_FORMAT_POWERSHELL: return "ps1";
    case DONUT_FORMAT_CSHARP:     return "cs";
    case DONUT_FORMAT_HEX:        return "hex";
    default:                      return "bin";
  }
}

// "<dir>/<input basename>.<ext>", used when a job has no output key.
static void derive_output(DONUT_CONFIG *c, const char *outdir) {
  const char *name = strrchr(c->input, '/');
  char stem[DONUT_MAX_NAME];
  size_t i = 0, n;

  name = (name != NULL) ? name + 1 : c->input;
  while (name[i] != 0 && name[i] != '.' && i < sizeof(stem) - 1) {
    stem[i] = name[i];
    i++;
  }
  stem[i] = 0;
  if (i == 0) copy_str(stem, "payload", sizeof(stem));

  n = strlen(outdir);
  {
    // Deliberately built wider than the destination, then clamped: a long
    // directory plus a long name truncates instead of overflowing.
    char tmp[DONUT_MAX_NAME * 2];
    snprintf(tmp, sizeof(tmp), "%s%s%s.%s", outdir,
             (n > 0 && outdir[n - 1] == '/') ? "" : "/", stem,
             format_ext(c->format));
    copy_str(c->output, tmp, sizeof(c->output));
  }
}

int RunProfile(const char *path, const char *outdir) {
  DONUT_CONFIG defaults, current, *jobs = NULL;
  FILE *fd;
  char line[PROFILE_LINE_MAX];
  int in_job = 0, job_started = 0, count = 0, failures = 0, i, err;
  char section[64];

  if (path == NULL || *path == 0) return 1;

  jobs = (DONUT_CONFIG *)calloc(PROFILE_MAX_JOBS, sizeof(DONUT_CONFIG));
  if (jobs == NULL) {
    printf("  [ profile: out of memory\n");
    return 1;
  }

  default_config(&defaults);
  current = defaults;
  section[0] = 0;

  fd = fopen(path, "r");
  if (fd == NULL) {
    printf("  [ profile: cannot open \"%s\"\n", path);
    free(jobs);
    return 1;
  }

  while (fgets(line, sizeof(line), fd) != NULL) {
    char *s = trim(line);
    char *eq;

    if (*s == 0 || *s == '#' || *s == ';') continue;

    if (*s == '[') {
      char *close = strchr(s, ']');
      size_t len;
      if (close == NULL) continue;
      *close = 0;
      copy_str(section, trim(s + 1), sizeof(section));

      if (!strcasecmp(section, "default")) {
        // A finished job is already queued; later keys go to the defaults.
        in_job = 0;
      } else {
        if (job_started) jobs[count++] = current;
        if (count >= PROFILE_MAX_JOBS) {
          printf("  [ profile: more than %d jobs, stopping\n", PROFILE_MAX_JOBS);
          break;
        }
        current = defaults;
        in_job = 1;
        job_started = 1;
      }
      len = 0; (void)len;
      continue;
    }

    eq = strchr(s, '=');
    if (eq == NULL) {
      printf("  [ profile: ignoring line without '=': %s\n", s);
      continue;
    }
    *eq = 0;
    {
      char *key = trim(s);
      char *val = trim(eq + 1);

      // Strip matching quotes.
      if ((*val == '"' && val[strlen(val) - 1] == '"') ||
          (*val == '\'' && val[strlen(val) - 1] == '\'')) {
        val[strlen(val) - 1] = 0;
        val++;
      }

      if (in_job) {
        apply_key(&current, key, val);
      } else {
        apply_key(&defaults, key, val);
      }
    }
  }
  fclose(fd);

  if (job_started) jobs[count++] = current;

  if (count == 0) {
    printf("  [ profile: no [job] sections in \"%s\"\n", path);
    free(jobs);
    return 1;
  }

  for (i = 0; i < count; i++) {
    DONUT_CONFIG *c = &jobs[i];

    if (c->input[0] == 0) {
      printf("  [ profile: job %d has no input, skipped\n", i + 1);
      failures++;
      continue;
    }

    if (outdir != NULL && *outdir != 0) {
      if (c->output[0] == 0)
        derive_output(c, outdir);
      else if (c->output[0] != '/') {
        char rel[DONUT_MAX_NAME], tmp[DONUT_MAX_NAME * 2];
        copy_str(rel, c->output, sizeof(rel));
        snprintf(tmp, sizeof(tmp), "%s/%s", outdir, rel);
        copy_str(c->output, tmp, sizeof(c->output));
      }
    } else if (c->output[0] == 0) {
      // Same default the CLI uses.
      copy_str(c->output, "loader.bin", sizeof(c->output));
    }

    printf("  [ job %d/%d : %s\n", i + 1, count, c->input);
    err = DonutCreate(c);
    if (err != DONUT_ERROR_OK) {
      printf("  [ Error : %s\n", DonutError(err));
      failures++;
    }
  }

  printf("  [ profile: %d job(s), %d failure(s)\n", count, failures);
  free(jobs);
  return failures == 0 ? 0 : 1;
}
