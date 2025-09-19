/* SPDX-License-Identifier: GPL-2.0-or-later */
/* X.509 certificate parser
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

// From https://lore.kernel.org/kvm/20240304065703.GA24373@wunner.de/T/

#ifndef X509_PARSER_H
#define X509_PARSER_H

#include <crypto/public_key.h>
#include <keys/asymmetric-type.h>
#include <linux/time64.h>

struct x509_certificate {
  struct x509_certificate     *next;
  struct x509_certificate     *signer;  /* Certificate that signed this one */
  struct public_key           *pub;     /* Public key details */
  struct public_key_signature *sig;     /* Signature parameters */
  char                        *issuer;  /* Name of certificate issuer */
  char                        *subject; /* Name of certificate subject */
  struct asymmetric_key_id    *id;      /* Issuer + Serial number */
  struct asymmetric_key_id    *skid;    /* Subject + subjectKeyId (optional) */
  time64_t                     valid_from;
  time64_t                     valid_to;
  const void                  *tbs;          /* Signed data */
  unsigned                     tbs_size;     /* Size of signed data */
  unsigned                     raw_sig_size; /* Size of signature */
  const void                  *raw_sig;      /* Signature data */
  const void                  *raw_serial;   /* Raw serial number in ASN.1 */
  unsigned                     raw_serial_size;
  unsigned                     raw_issuer_size;
  const void                  *raw_issuer;  /* Raw issuer name in ASN.1 */
  const void                  *raw_subject; /* Raw subject name in ASN.1 */
  unsigned                     raw_subject_size;
  unsigned                     raw_skid_size;
  const void                  *raw_skid; /* Raw subjectKeyId in ASN.1 */
  unsigned                     index;
  bool                         seen; /* Infinite recursion prevention */
  bool                         verified;
  bool self_signed;     /* T if self-signed (check unsupported_sig too) */
  bool unsupported_sig; /* T if signature uses unsupported crypto */
  bool blacklisted;
};

struct x509_certificate *x509_cert_parse(const void *data, size_t datalen);
void                     x509_free_certificate(struct x509_certificate *cert);

#endif