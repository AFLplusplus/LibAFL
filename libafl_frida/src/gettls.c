void * get_tls_ptr() {
        return __builtin_thread_pointer();
}
