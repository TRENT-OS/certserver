/**
 * Copyright (C) 2020, Hensoldt Cyber GmbH
 *
 * @defgroup CertServer
 * @{
 *
 * @file
 * @brief CertServer client interface
 *
 */

#pragma once

#include "OS_CertParser.h"

#include "if_CertServer.h"

#include <camkes.h>

OS_Error_t
CertServer_initChain(
    const if_CertServer_t* rpc);

OS_Error_t
CertServer_addCertToChain(
    const if_CertServer_t*             rpc,
    const OS_CertParserCert_Encoding_t encoding,
    const uint8_t*                     data,
    const size_t                       len);

OS_Error_t
CertServer_verifyChain(
    const if_CertServer_t*       rpc,
    OS_CertParser_VerifyFlags_t* result);

OS_Error_t
CertServer_freeChain(
    const if_CertServer_t* rpc);

/** @} */