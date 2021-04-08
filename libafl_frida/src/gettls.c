void * get_tls_ptr() {
        void * address = 0;
        __asm("mrs %[result], tpidr_el0": [result] "=r" (address));
        return address;
}
