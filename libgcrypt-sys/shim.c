#include <errno.h>
#include <pthread.h>
#include <gcrypt.h>

GCRY_THREAD_OPTION_PTHREAD_IMPL;
struct gcry_threads_cbs *gcry_threads_pthread_shim(void) {
  return &gcry_threads_pthread;
}
