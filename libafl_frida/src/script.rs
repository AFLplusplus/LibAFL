use {
    crate::bindings::{
        _frida_g_main_context_push_thread_default, _frida_g_main_loop_new, gchar, gpointer,
        gum_init_embedded, gum_script_backend_create, gum_script_backend_create_finish,
        gum_script_backend_get_scheduler, gum_script_backend_obtain_qjs, gum_script_load,
        gum_script_load_finish, gum_script_scheduler_disable_background_thread,
        gum_script_scheduler_get_js_context, gum_script_set_message_handler, GAsyncResult, GBytes,
        GCancellable, GError, GObject, GumScript, GumScriptBackend,
        _frida_g_main_context_iteration, _frida_g_main_context_pending,
    },
    anyhow::Result,
    std::{
        ffi::{c_void, CStr, CString},
        fs::File,
        io::Read,
        path::Path,
        ptr::null_mut,
    },
};

// TODO
// Check and handle errors

/// A Frida Script
#[derive(Debug)]
pub struct Script;

/// A Frida Script
impl Script {
    /// Create a new Script
    pub fn load<P: AsRef<Path>>(path: P) -> Result<()> {
        unsafe {
            gum_init_embedded();
            let scheduler = gum_script_backend_get_scheduler();
            gum_script_scheduler_disable_background_thread(scheduler);
            let backend = gum_script_backend_obtain_qjs();

            let script_prefix = include_str!("script.js");

            let mut file = File::open(path.as_ref())?;
            let mut file_string = String::new();
            file.read_to_string(&mut file_string)?;

            let payload = script_prefix.to_string() + &file_string;
            println!("payload: {payload:}");

            let payload_cstring = CString::new(payload)?;
            let payload_data = payload_cstring.as_ptr();

            let context = gum_script_scheduler_get_js_context(scheduler);
            _frida_g_main_loop_new(context, 1);
            _frida_g_main_context_push_thread_default(context);

            let name_cstring = CString::new("example")?;
            let name_ptr = name_cstring.as_ptr();

            // set to null
            let snapshot: *mut GBytes = null_mut();
            let cancellable: *mut GCancellable = null_mut();

            gum_script_backend_create(
                backend,
                name_ptr,
                payload_data as *const gchar,
                snapshot,
                cancellable,
                Some(Script::create_cb),
                backend as *mut c_void,
            );

            while _frida_g_main_context_pending(context) != 0 {
                _frida_g_main_context_iteration(context, 0);
            }

            Ok(())
        }
    }

    unsafe extern "C" fn create_cb(
        _source_object: *mut GObject,
        result: *mut GAsyncResult,
        user_data: gpointer,
    ) {
        let backend = user_data as *mut GumScriptBackend;
        let mut error: *mut GError = null_mut();
    
        let script = gum_script_backend_create_finish(backend, result, &mut error as *mut *mut GError);
        if script == null_mut() {
            todo!();
        }
    
        gum_script_set_message_handler(script, Some(Script::js_msg), user_data, None);
    
        let cancellable: *mut GCancellable = null_mut();
        gum_script_load(script, cancellable, Some(Script::load_cb), script as *mut c_void);
    }

    unsafe extern "C" fn js_msg(message: *const gchar, _data: *mut GBytes, _user_data: gpointer) {
        if let Ok(msg) = CStr::from_ptr(message).to_str() {
            println!("{}", msg);
        }
    }

    unsafe extern "C" fn load_cb(
        _source_object: *mut GObject,
        result: *mut GAsyncResult,
        user_data: gpointer,
    ) {
        let script = user_data as *mut GumScript;
        gum_script_load_finish(script, result);
    }
}



/// Callback function which can be called from the script
#[no_mangle]
pub extern "C" fn test_function(message: *const gchar) {
    if let Ok(msg) = unsafe { CStr::from_ptr(message).to_str() } {
        println!("{}", msg);
    }
}
