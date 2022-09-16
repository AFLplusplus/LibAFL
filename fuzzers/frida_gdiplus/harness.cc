// libpng_read_fuzzer.cc
// Copyright 2017-2018 Glenn Randers-Pehrson
// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that may
// be found in the LICENSE file https://cs.chromium.org/chromium/src/LICENSE

// Last changed in libpng 1.6.35 [July 15, 2018]

// The modifications in 2017 by Glenn Randers-Pehrson include
// 1. addition of a PNG_CLEANUP macro,
// 2. setting the option to ignore ADLER32 checksums,
// 3. adding "#include <string.h>" which is needed on some platforms
//    to provide memcpy().
// 4. adding read_end_info() and creating an end_info structure.
// 5. adding calls to png_set_*() transforms commonly used by browsers.

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

wchar_t* charToWChar(const char* text)
{
    size_t size = strlen(text) + 1;
    wchar_t* wa = new wchar_t[size];
    mbstowcs(wa,text,size);
    return wa;
}


GdiplusStartupInput gdiplusStartupInput;
ULONG_PTR gdiplusToken;

extern "C" int afl_libfuzzer_init() {
  GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);


  return 0;
}

// static char * allocation = NULL;
// __attribute__((noinline))
// void func3( char * alloc) {
//   //printf("func3\n");
//   #ifdef _WIN32
//   if (rand() == 0) {
//     alloc[0x1ff] = 0xde;
//     printf("alloc[0x200]: %d\n", alloc[0x200]);
//   }
//   #else
//   if (random() == 0) {
//     alloc[0x1ff] = 0xde;
//     printf("alloc[0x200]: %d\n", alloc[0x200]);
//   }
//   #endif
// }
// __attribute__((noinline))
// void func2() {
//   allocation = (char*)malloc(0xff);
//   //printf("func2\n");
//   func3(allocation);
// }
// __attribute__((noinline))
// void func1() {
//   //printf("func1\n");
//   func2();
// }

// Export this symbol
#	define HARNESS_EXPORTS __declspec(dllexport)

// Entry point for LibFuzzer.
// Roughly follows the libpng book example:
// http://www.libpng.org/pub/png/book/chapter13.html


DWORD init = 0;


extern "C" __declspec(dllexport)  int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if(!init)
  {
    GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
    init = 1; 
  }


    HGLOBAL m_hBuffer  = ::GlobalAlloc(GMEM_MOVEABLE, size);
    if (m_hBuffer)
    {
        void* pBuffer = ::GlobalLock(m_hBuffer);
        if (pBuffer)
        {
            CopyMemory(pBuffer, data, size);

            IStream* pStream = NULL;
            if (::CreateStreamOnHGlobal(m_hBuffer, FALSE, &pStream) == S_OK)
            {
                Gdiplus::Bitmap *m_pBitmap = Gdiplus::Bitmap::FromStream(pStream);
                pStream->Release();
                if (m_pBitmap)
                { 
                  if (m_pBitmap->GetLastStatus() == Gdiplus::Ok)
                    return true;

                  delete m_pBitmap;
                  m_pBitmap = NULL;
                }
            }
            ::GlobalUnlock(m_hBuffer);
        }        
        ::GlobalFree(m_hBuffer);
        m_hBuffer = NULL;
    }
    

    //GdiplusShutdown(gdiplusToken);
    
    return 0;
    
}

