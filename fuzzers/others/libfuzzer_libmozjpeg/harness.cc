#include <stdio.h>
#include "jpeglib.h"
#include <setjmp.h>
#include <stdint.h>

struct my_error_mgr {
  struct jpeg_error_mgr pub; /* "public" fields */

  jmp_buf setjmp_buffer; /* for return to caller */
};

typedef struct my_error_mgr *my_error_ptr;

/*
 * Here's the routine that will replace the standard error_exit method:
 */

METHODDEF(void)
my_error_exit(j_common_ptr cinfo) {
  /* cinfo->err really points to a my_error_mgr struct, so coerce pointer */
  my_error_ptr myerr = (my_error_ptr)cinfo->err;

  /* Always display the message. */
  /* We could postpone this until after returning, if we chose. */
  (*cinfo->err->output_message)(cinfo);

  /* Return control to the setjmp point */
  longjmp(myerr->setjmp_buffer, 1);
}

int do_read_JPEG_file(struct jpeg_decompress_struct *cinfo,
                      const uint8_t *input, size_t len) {
  struct my_error_mgr jerr;
  /* More stuff */
  JSAMPARRAY buffer;     /* Output row buffer */
  int        row_stride; /* physical row width in output buffer */
  /* Step 1: allocate and initialize JPEG decompression object */
  /* We set up the normal JPEG error routines, then override error_exit. */
  cinfo->err = jpeg_std_error(&jerr.pub);
  jerr.pub.error_exit = my_error_exit;
  /* Establish the setjmp return context for my_error_exit to use. */
  if (setjmp(jerr.setjmp_buffer)) {
    jpeg_destroy_decompress(cinfo);
    return 0;
  }
  /* Now we can initialize the JPEG decompression object. */
  jpeg_create_decompress(cinfo);
  /* Step 2: specify data source (eg, a file) */
  jpeg_mem_src(cinfo, input, len);
  /* Step 3: read file parameters with jpeg_read_header() */
  (void)jpeg_read_header(cinfo, TRUE);
  /* Step 4: set parameters for decompression */
  /* In this example, we don't need to change any of the defaults set by
   * jpeg_read_header(), so we do nothing here.
   */
  /* Step 5: Start decompressor */
  (void)jpeg_start_decompress(cinfo);
  /* JSAMPLEs per row in output buffer */
  row_stride = cinfo->output_width * cinfo->output_components;
  /* Make a one-row-high sample array that will go away when done with image */
  buffer = (*cinfo->mem->alloc_sarray)((j_common_ptr)cinfo, JPOOL_IMAGE,
                                       row_stride, 1);
  /* Step 6: while (scan lines remain to be read) */
  /*           jpeg_read_scanlines(...); */
  while (cinfo->output_scanline < cinfo->output_height) {
    (void)jpeg_read_scanlines(cinfo, buffer, 1);
    /* Assume put_scanline_someplace wants a pointer and sample count. */
    // put_scanline_someplace(buffer[0], row_stride);
  }
  /* Step 7: Finish decompression */
  (void)jpeg_finish_decompress(cinfo);
  /* Step 8: Release JPEG decompression object */
  // jpeg_destroy_decompress(cinfo);
  return 1;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct jpeg_decompress_struct cinfo;
  do_read_JPEG_file(&cinfo, data, size);
  return 0;
}
