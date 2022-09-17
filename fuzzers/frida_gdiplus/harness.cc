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
          if (m_pBitmap->GetLastStatus() == Gdiplus::Ok) return true;

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
