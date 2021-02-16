fn main() {

  #[cfg(target_os = "windows")]
  windows::build!(
      // API needed for the shared memory
      windows::win32::system_services::{CreateFileMappingA, MapViewOfFile, UnmapViewOfFile},
      windows::win32::windows_programming::CloseHandle
  );

}
