/* Copyright (C) 2020, HENSOLDT Cyber GmbH */

#pragma once

#include "OS_CertParser.h"
#include "OS_Dataport.h"
#include "OS_Error.h"

#include <stdint.h>

typedef struct
{
    OS_Error_t (*initChain)(
        void);
    OS_Error_t (*addCertToChain)(
        const OS_CertParserCert_Encoding_t encoding,
        const size_t                       len);
    OS_Error_t (*verifyChain)(
        OS_CertParser_VerifyFlags_t* result);
    OS_Error_t (*freeChain)(
        void);
    OS_Dataport_t dataport;
} if_CertServer_t;

#define IF_CERTSERVER_ASSIGN(_rpc_, _port_) \
    { \
        .initChain      = _rpc_ ## _initChain, \
        .addCertToChain = _rpc_ ## _addCertToChain, \
        .verifyChain    = _rpc_ ## _verifyChain, \
        .freeChain      = _rpc_ ## _freeChain, \
        .dataport       = OS_DATAPORT_ASSIGN(_port_) \
    }
