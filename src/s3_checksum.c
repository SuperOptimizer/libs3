/*
 * libs3 -- Checksum computation placeholder
 *
 * Checksum computation (CRC32, CRC32C, SHA-1, SHA-256) is handled inline
 * in s3_object.c (for object upload/download integrity) and s3_crypto.c
 * (for the core hash implementations).  No additional functions are needed
 * in this translation unit for now.
 */

#include "s3_internal.h"
