/* Copyright (C) 2020, Hensoldt Cyber GmbH */

#include "OS_CertParser.h"

#include "LibDebug/Debug.h"
#include "LibMacros/Check.h"
#include "LibContext/ContextMgr.h"

#include <stdint.h>

#include <camkes.h>

#define CERTSERVER_CLIENTS_MAX 8
#define CERTSERVER_CID_MIN 101
#define CERTSERVER_CID_MAX ((CERTSERVER_CID_MIN - 1) + CERTSERVER_CLIENTS_MAX)

seL4_Word certServer_rpc_get_sender_id(
    void);

// Client context
typedef struct
{
    OS_CertParserChain_Handle_t hChain;
    const OS_Dataport_t* port;
    seL4_Word cid;
} CertServer_Client_t;

// Client context manager instance
static ContextMgr_t contextMgr;
// CertParser and trusted chain instances
static OS_CertParser_Handle_t hParser;
static OS_CertParserChain_Handle_t hChain;

// Private functions -----------------------------------------------------------

static OS_Error_t
initClient(
    const ContextMgr_CID_t cid,
    void**                 mem)
{
    static const OS_Dataport_t ports[CERTSERVER_CLIENTS_MAX] =
    {
        OS_DATAPORT_ASSIGN(certServer_port1),
        OS_DATAPORT_ASSIGN(certServer_port2),
        OS_DATAPORT_ASSIGN(certServer_port3),
        OS_DATAPORT_ASSIGN(certServer_port4),
        OS_DATAPORT_ASSIGN(certServer_port5),
        OS_DATAPORT_ASSIGN(certServer_port6),
        OS_DATAPORT_ASSIGN(certServer_port7),
        OS_DATAPORT_ASSIGN(certServer_port8),
    };
    CertServer_Client_t* ctx;

    // Make sure CID is in expected range
    if (cid < CERTSERVER_CID_MIN || cid > CERTSERVER_CID_MAX)
    {
        Debug_LOG_ERROR("Cannot allocate client context, invalid " \
                        "client ID (CID=%i). Make sure to assign client " \
                        "badges properly.", cid);
        return OS_ERROR_INVALID_PARAMETER;
    }

    // Alloc client struct
    if ((ctx = calloc(1, sizeof(CertServer_Client_t))) == NULL)
    {
        Debug_LOG_ERROR("calloc() failed");
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    // Assign CID and dataport.
    ctx->cid  = cid;
    ctx->port = &ports[cid - CERTSERVER_CID_MIN];

    *mem = ctx;

    return OS_SUCCESS;
}

static OS_Error_t
freeClient(
    const ContextMgr_CID_t cid,
    void*                  mem)
{
    free(mem);

    return OS_SUCCESS;
}

// Public functions ------------------------------------------------------------

void
post_init()
{
    const ContextMgr_MemoryFuncs_t fns =
    {
        .init = initClient,
        .free = freeClient
    };
    const OS_Crypto_Config_t cfgCrypto =
    {
        .mode = OS_Crypto_MODE_LIBRARY,
        .entropy = IF_OS_ENTROPY_ASSIGN(
            entropy_rpc,
            entropy_port),
    };
    OS_CertParser_Config_t cfgParser;
    OS_CertParserCert_Handle_t hCert;
    OS_Error_t err;

    // Check we have "some" certs configured
    Debug_ASSERT_PRINTFLN(certServer_cfg.numCerts != 0,
                          "No trusted certs are configured");

    // Create context manager for clients
    if ((err = ContextMgr_init(&contextMgr, &fns,
                               CERTSERVER_CLIENTS_MAX)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("ContextMgr_init() failed with %i", err);
        return;
    }

    // Init crypto and cert parser
    if ((err = OS_Crypto_init(&cfgParser.hCrypto, &cfgCrypto)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_Crypto_init() failed with %i", err);
        return;
    }
    if ((err = OS_CertParser_init(&hParser, &cfgParser)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CertParser_init() failed with %i", err);
        return;
    }

    // Construct chain of root and intermediate cert
    if ((err = OS_CertParserChain_init(&hChain, hParser)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CertParserChain_init() failed with %i", err);
        return;
    }
    for (size_t i = 0; i < certServer_cfg.numCerts; i++)
    {
        Debug_ASSERT_PRINTFLN(strlen(certServer_cfg.trustedCerts[i]) != 0,
                              "Trusted cert at index %Zd is empty", i);
        if ((err = OS_CertParserCert_init(
                       &hCert,
                       hParser,
                       OS_CertParserCert_Encoding_PEM,
                       (uint8_t*)certServer_cfg.trustedCerts[i],
                       strlen(certServer_cfg.trustedCerts[i]))) != OS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_CertParserCert_init() failed with %i", err);
            return;
        }
        if ((err = OS_CertParserChain_addCert(hChain, hCert)) != OS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_CertParserChain_addCert() failed with %i", err);
            return;
        }
    }

    // Add chain to parser
    if ((err = OS_CertParser_addTrustedChain(hParser, hChain)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CertParserChain_addCert() failed with %i", err);
        return;
    }
}

OS_Error_t
NONNULL_ALL
certServer_rpc_initChain(
    void)
{
    OS_Error_t err;
    CertServer_Client_t* client;

    if ((err = ContextMgr_get(&contextMgr, certServer_rpc_get_sender_id(),
                              (void**)&client)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("ContextMgr_get() failed with %i", err);
        return err;
    }

    // Make sure we don't have chain already
    if (client->hChain != NULL)
    {
        Debug_LOG_ERROR("Chain is already initialized");
        return OS_ERROR_INVALID_STATE;
    }

    // Construct chain of root and intermediate cert
    if ((err = OS_CertParserChain_init(&client->hChain, hParser)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CertParserChain_init() failed with %i", err);
        return err;
    }

    return OS_SUCCESS;
}

OS_Error_t
NONNULL_ALL
certServer_rpc_addCertToChain(
    const OS_CertParserCert_Encoding_t encoding,
    const size_t                       len)
{
    OS_Error_t err;
    OS_CertParserCert_Handle_t hCert;
    CertServer_Client_t* client;

    if ((err = ContextMgr_get(&contextMgr, certServer_rpc_get_sender_id(),
                              (void**)&client)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("ContextMgr_get() failed with %i", err);
        return err;
    }

    CHECK_VALUE_IN_CLOSED_INTERVAL(len, 0, OS_Dataport_getSize(*client->port));
    CHECK_VALUE_NOT_ZERO(len);

    // Make sure we actually have a chain
    if (client->hChain == NULL)
    {
        Debug_LOG_ERROR("Chain is not initialized yet");
        return OS_ERROR_INVALID_STATE;
    }

    // Create cert; these will be associated with the client's chain so we do
    // not need to track the memory further; the certs will be freed with the
    // chain..
    if ((err = OS_CertParserCert_init(
                   &hCert,
                   hParser,
                   encoding,
                   OS_Dataport_getBuf(*client->port),
                   len)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CertParserCert_init() failed with %i", err);
        return err;
    }
    if ((err = OS_CertParserChain_addCert(client->hChain, hCert)) != OS_SUCCESS)
    {
        OS_CertParserCert_free(hCert);
        Debug_LOG_ERROR("OS_CertParserChain_addCert() failed with %i", err);
        return err;
    }

    return OS_SUCCESS;
}

OS_Error_t
NONNULL_ALL
certServer_rpc_verifyChain(
    OS_CertParser_VerifyFlags_t* result)
{
    OS_Error_t err;
    CertServer_Client_t* client;

    if ((err = ContextMgr_get(&contextMgr, certServer_rpc_get_sender_id(),
                              (void**)&client)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("ContextMgr_get() failed with %i", err);
        return err;
    }

    // Make sure we actually have a chain
    if (client->hChain == NULL)
    {
        Debug_LOG_ERROR("Chain is not initialized yet");
        return OS_ERROR_INVALID_STATE;
    }

    return OS_CertParser_verifyChain(hParser, 0, client->hChain, result);
}

OS_Error_t
NONNULL_ALL
certServer_rpc_freeChain(
    void)
{
    OS_Error_t err;
    CertServer_Client_t* client;

    if ((err = ContextMgr_get(&contextMgr, certServer_rpc_get_sender_id(),
                              (void**)&client)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("ContextMgr_get() failed with %i", err);
        return err;
    }

    // Make sure we actually have a chain
    if (client->hChain == NULL)
    {
        Debug_LOG_ERROR("Chain is not initialized yet");
        return OS_ERROR_INVALID_STATE;
    }

    // Free chain and all associated certs as well
    if ((err = OS_CertParserChain_free(client->hChain, true)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CertParserChain_init() failed with %i", err);
        return err;
    }

    client->hChain = NULL;

    return OS_SUCCESS;
}