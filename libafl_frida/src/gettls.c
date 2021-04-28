#ifdef _MSC_VER
__declspec( thread ) int i = 0;
#else
__thread int i = 0;
#endif

void * get_tls_ptr() {
        return (void*)&i;
}
