#ifdef _MSC_VER
thread_local int i;
#else
__thread int i;
#endif

void * get_tls_ptr() {
        return (void*)&i;
}
