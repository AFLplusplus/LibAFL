#ifdef _MSC_VER
__declspec(thread) int i = 0;
#else
__thread int i = 0;
#endif

void *tls_ptr() {
  return (void *)&i;
}
