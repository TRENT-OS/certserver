/* Copyright (C) 2020, Hensoldt Cyber GmbH */

#include "CertServer.h"
#include "lib_macros/Check.h"

OS_Error_t
CertServer_initChain(
    const if_CertServer_t* rpc)
{
    CHECK_PTR_NOT_NULL(rpc);

    return rpc->initChain();
}

OS_Error_t
CertServer_addCertToChain(
    const if_CertServer_t*             rpc,
    const OS_CertParserCert_Encoding_t encoding,
    const uint8_t*                     data,
    const size_t                       len)
{
    CHECK_PTR_NOT_NULL(rpc);
    CHECK_PTR_NOT_NULL(data);

    CHECK_VALUE_IN_CLOSED_INTERVAL(len, 0, OS_Dataport_getSize(rpc->dataport));

    memcpy(OS_Dataport_getBuf(rpc->dataport), data, len);

    return rpc->addCertToChain(encoding, len);
}

OS_Error_t
CertServer_verifyChain(
    const if_CertServer_t*       rpc,
    OS_CertParser_VerifyFlags_t* result)
{
    CHECK_PTR_NOT_NULL(rpc);
    CHECK_PTR_NOT_NULL(result);

    return rpc->verifyChain(result);
}

OS_Error_t
CertServer_freeChain(
    const if_CertServer_t* rpc)
{
    CHECK_PTR_NOT_NULL(rpc);

    return rpc->freeChain();
}