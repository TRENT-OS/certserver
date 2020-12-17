/* Copyright (C) 2020, Hensoldt Cyber GmbH */

#include "CertServer.h"

OS_Error_t
CertServer_initChain(
    const if_CertServer_t* rpc)
{
    return OS_ERROR_NOT_IMPLEMENTED;
}

OS_Error_t
CertServer_addCertToChain(
    const if_CertServer_t*             rpc,
    const OS_CertParserCert_Encoding_t encoding,
    const uint8_t*                     data,
    const size_t                       len)
{
    return OS_ERROR_NOT_IMPLEMENTED;
}

OS_Error_t
CertServer_verifyChain(
    const if_CertServer_t*       rpc,
    OS_CertParser_VerifyFlags_t* result)
{
    return OS_ERROR_NOT_IMPLEMENTED;
}

OS_Error_t
CertServer_freeChain(
    const if_CertServer_t *rpc)
{
    return OS_ERROR_NOT_IMPLEMENTED;
}