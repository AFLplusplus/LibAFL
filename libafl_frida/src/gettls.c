__thread int i;

void * get_tls_ptr() {
        return (void*)&i;
}
