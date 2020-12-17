#
# CertServer CMake file
#
# Copyright (C) 2020, Hensoldt Cyber GmbH
#

cmake_minimum_required(VERSION 3.17)


#-------------------------------------------------------------------------------
#
# Declare CertServer CAmkES Component
#
# Parameters:
#
#   <name>
#     component instance name. The server will be called "<name>" and the
#     corresponding client library will be called "<name>_client"
#
function(CertServer_DeclareCAmkESComponent
    name
)

    #---------------------------------------------------------------------------
    DeclareCAmkESComponent(${name}
        SOURCES
            ${CMAKE_CURRENT_FUNCTION_LIST_DIR}/server/src/certServer_rpc.c
        C_FLAGS
            -Wall
            -Werror
        LIBS
            os_core_api
            os_libs
            os_crypto
            os_cert
    )

    #---------------------------------------------------------------------------
    # create the corresponding client project, which every client of this
    # CertServer instance must include. We do not define this globally,
    # because the clients may have server specific configurations in the
    # future.
    project(${name}_client C)

    add_library(${PROJECT_NAME} INTERFACE)

    target_sources(${PROJECT_NAME}
        INTERFACE
            ${CMAKE_CURRENT_FUNCTION_LIST_DIR}/client/src/CertServer.c
    )

    target_include_directories(${PROJECT_NAME}
        INTERFACE
            ${CMAKE_CURRENT_FUNCTION_LIST_DIR}/client/include
    )

endfunction()
