#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <vector>
#include <iostream>

#include <windows.h>
#include <gdiplus.h>

using namespace std;
using namespace Gdiplus;

GdiplusStartupInput gdiplusStartupInput;
ULONG_PTR           gdiplusToken;

// Some DLLs are lazily loaded during image loading
// FridaInstrumentationHelper doesn't instrument DLLs that are loaded after
// init, so they're manually loaded here
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
      LoadLibraryA("gdi32full.dll");
      LoadLibraryA("WindowsCodecs.dll");
      break;
  }
  return TRUE;
}

extern "C" __declspec(dllexport) int LLVMFuzzerTestOneInput(const uint8_t *data,
                                                            size_t size) {
  static DWORD init = 0;
  if (!init) {
    GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
    init = 1;
  }

  HGLOBAL m_hBuffer = ::GlobalAlloc(GMEM_MOVEABLE, size);
  if (m_hBuffer) {
    void *pBuffer = ::GlobalLock(m_hBuffer);
    if (pBuffer) {
      CopyMemory(pBuffer, data, size);

      IStream *pStream = NULL;
      if (::CreateStreamOnHGlobal(m_hBuffer, FALSE, &pStream) == S_OK) {
        Gdiplus::Bitmap *m_pBitmap = Gdiplus::Bitmap::FromStream(pStream);
        pStream->Release();
        if (m_pBitmap) {
          delete m_pBitmap;
          m_pBitmap = NULL;
        }
      }
      ::GlobalUnlock(m_hBuffer);
    }
    ::GlobalFree(m_hBuffer);
    m_hBuffer = NULL;
  }

  // GdiplusShutdown(gdiplusToken);
  return 0;
}
