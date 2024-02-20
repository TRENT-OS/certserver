/*
 * Copyright (C) 2020-2024, HENSOLDT Cyber GmbH
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
 */

/**
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

/**
 * @brief Initialize a certificate chain
 *
 * Initialize a chain to which we then can add certificates for verification
 * against the CertServer's preconfigured, trusted chain. There can only be
 * a single chain at a time.
 *
 * @param rpc (required)
 *
 * @return an error code
 * @retval OS_SUCCESS if operation succeeded
 * @retval OS_ERROR_INVALID_PARAMETER if a parameter was missing or invalid
 * @retval OS_ERROR_INVALID_STATE if chain was already initialized
 * @retval OTHER (more error codes may be passed through from the CertParser lib)
 */
OS_Error_t
CertServer_initChain(
    const if_CertServer_t* rpc  /**< [in]   pointer to CAmkES rpc struct */
);

/**
 * @brief Add cert to chain
 *
 * Add a certificate to a chain. They will internally be stored and associatex
 * with the chain. Certs will be free'd when the chain is free'd.
 *
 * NOTE: Make sure that certificates actually form a chain, (e.g., the second
 *       cert is signed by the first, the third by the second, etc.).
 *
 * @return an error code
 * @retval OS_SUCCESS if operation succeeded
 * @retval OS_ERROR_INVALID_PARAMETER if a parameter was missing or invalid
 * @retval OS_ERROR_INVALID_STATE if chain was not yet initialized
 * @retval OTHER (more error codes may be passed through from the CertParser lib)
 */
OS_Error_t
CertServer_addCertToChain(
    const if_CertServer_t*             rpc,         /**< [in]   pointer to CAmkES
                                                                rpc struct */
    const OS_CertParserCert_Encoding_t encoding,    /**< [in]   encoding type (DER
                                                                or PEM) */
    const uint8_t*                     data,        /**< [in]   cert data */
    const size_t
    len          /**< [in]   length of cert data */
);

/**
 * @brief Verify a chain against the preconfigured, trusted chain of the CertServer
 *
 * After constructing a chain, verify it against the trusted chain in the
 * CertServer.
 *
 * @return an error code
 * @retval OS_SUCCESS if operation succeeded
 * @retval OS_ERROR_INVALID_PARAMETER if a parameter was missing or invalid
 * @retval OS_ERROR_INVALID_STATE if chain was not yet initialized
 * @retval OS_ERROR_GENERIC if the verification failed, the exact failure
 *  condition is indicated by \p result
 * @retval OTHER (more error codes may be passed through from the CertParser lib)
 */
OS_Error_t
CertServer_verifyChain(
    const if_CertServer_t*       rpc,       /**< [in]   pointer to CAmkES rpc
                                                        struct */
    OS_CertParser_VerifyFlags_t* result     /**< [in]   flag indicating type of
                                                        verification failure */
);

/**
 * @brief Free a cert chain
 *
 * Free a certificate chain; this will also free all associated certs.
 *
 * @return an error code
 * @retval OS_SUCCESS if operation succeeded
 * @retval OS_ERROR_INVALID_PARAMETER if a parameter was missing or invalid
 * @retval OS_ERROR_INVALID_STATE if chain was not yet initialized
 * @retval OTHER (more error codes may be passed through from the CertParser lib)
 */
OS_Error_t
CertServer_freeChain(
    const if_CertServer_t* rpc  /**< [in]   pointer to CAmkES rpc struct */
);

/** @} */