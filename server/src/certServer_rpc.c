/* Copyright (C) 2020, Hensoldt Cyber GmbH */

#include "OS_CertParser.h"

#include <stdint.h>

#include <camkes.h>

void
post_init()
{
}

OS_Error_t
NONNULL_ALL
certServer_rpc_initChain(
    void)
{
    return OS_ERROR_NOT_IMPLEMENTED;
}

OS_Error_t
NONNULL_ALL
certServer_rpc_addCertToChain(
    const OS_CertParserCert_Encoding_t encoding,
    const size_t                       len)
{
    return OS_ERROR_NOT_IMPLEMENTED;
}

OS_Error_t
NONNULL_ALL
certServer_rpc_verifyChain(
    OS_CertParser_VerifyFlags_t* result)
{
    return OS_ERROR_NOT_IMPLEMENTED;
}

OS_Error_t
NONNULL_ALL
certServer_rpc_freeChain(
    void)
{
    return OS_ERROR_NOT_IMPLEMENTED;
}
