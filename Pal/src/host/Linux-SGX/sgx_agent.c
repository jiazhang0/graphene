/* Copyright (C) 2019, Texas A&M University.

   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include <pal_linux.h>
#include <pal_rtld.h>
#include <pal_crypto.h>
#include <hex.h>

#include "sgx_internal.h"
#include "sgx_arch.h"
#include "sgx_enclave.h"
#include "sgx_attest.h"
#include "quote/aesm.pb-c.h"

#include <asm/errno.h>
#include <linux/fs.h>
#include <linux/un.h>
#define __USE_XOPEN2K8
#include <stdlib.h>

#define RA_AGENT_BACKLOG        10

static int agent_sock = -1;
static int agent_cfd = -1;

int init_graphene_agent(void)
{
    int sock = INLINE_SYSCALL(socket, 3, AF_UNIX, SOCK_STREAM, 0);
    if (IS_ERR(sock))
        return sock;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    (void)strcpy_static(addr.sun_path, "/var/run/graphene/agent.sock", sizeof(addr.sun_path));

    /* This will fail if the socket doesn't already exist.
     * Ignore the error.
     */
    INLINE_SYSCALL(unlink, 1, addr.sun_path);

    int ret = INLINE_SYSCALL(bind, 3, sock, &addr, sizeof(addr));
    if (IS_ERR(ret))
        goto err;

    ret = INLINE_SYSCALL(listen, 2, sock, RA_AGENT_BACKLOG);
    if (IS_ERR(ret))
        goto err;

    agent_sock = sock;
    return 0;

err:
    INLINE_SYSCALL(close, 1, sock);
    return ret;
}

int retrieve_agent_request(uint32_t* type, void** payload, uint32_t* payload_len)
{
    static void* payload_buf;
    static uint32_t payload_buf_len;

    if (agent_sock < 0) {
        agent_sock = init_graphene_agent();
        if (agent_sock < 0)
            return agent_sock;

        assert(agent_cfd < 0);
    }

    while (1) {
        if (agent_cfd < 0) {
            assert(agent_sock >= 0);

            struct sockaddr c_addr;
            socklen_t addrlen = sizeof(c_addr);
            agent_cfd = INLINE_SYSCALL(accept4, 4, agent_sock, &c_addr, &addrlen, O_CLOEXEC);
            if (IS_ERR(agent_cfd))
                return agent_cfd;

            SGX_DBG(DBG_I, "Agent connection established\n");
        }

        uint32_t req;
        int ret = INLINE_SYSCALL(read, 3, agent_cfd, &req, sizeof(req));
        if (ret != sizeof(req)) {
            SGX_DBG(DBG_D, "rx type with %d\n", ret);
            if (ret >= 0)
                ret = -EINVAL;
            goto err;
        }

        if (req >= AGENT_REQ_TYPE_MAX) {
            ret = -ENODEV;
            goto err;
        }

        uint32_t plen;
        ret = INLINE_SYSCALL(read, 3, agent_cfd, &plen, sizeof(plen));
        if (ret != sizeof(plen)) {
            SGX_DBG(DBG_D, "rx plen with %d\n", ret);
            if (ret >= 0)
                ret = -EINVAL;
            goto err;
        }

        void* p = payload_buf; 
        if (payload_buf_len < plen) {
            void* new_p = malloc(plen);
            if (!new_p) {
                ret = -ENOMEM;
                goto err;
            }

            free(payload_buf);
            payload_buf = p = new_p;
            payload_buf_len = plen;
        }

        ret = INLINE_SYSCALL(read, 3, agent_cfd, p, plen);
        if (ret != (int)plen) {
            SGX_DBG(DBG_D, "rx payload with %d (%d)\n", ret, plen);
            if (ret >= 0)
                ret = -EINVAL;
            goto err;
        }

        *type = req;
        *payload = p;
        *payload_len = plen;

        SGX_DBG(DBG_D, "retrieve_agent_request: req %x, plen %d\n", req, plen);

        return 0;

err:
        INLINE_SYSCALL(close, 1, agent_cfd);
        agent_cfd = -1;
        if (payload_buf) {
            free(payload_buf);
            payload_buf = NULL;
        }
        payload_buf_len = 0;
        SGX_DBG(DBG_D, "Failed to retrieve_agent_request with %d\n", ret);
    }

    return 0;
}

int respond_agent_request(uint32_t status, void* p, uint32_t plen)
{
    if (agent_cfd < 0)
        return -1;

    void* data_to_send[] = { &status, &plen, p };
    uint32_t sz[] = { sizeof(status), sizeof(plen), plen };
    int ret = 0;

    for (unsigned int i = 0; i < ARRAY_SIZE(data_to_send); ++i) {
        ret = INLINE_SYSCALL(write, 3, agent_cfd, data_to_send[i], sz[i]);
        if (ret != (int)sz[i]) {
            SGX_DBG(DBG_D, "tx payload with %d (%d)\n", ret, plen);
            if (ret >= 0)
                ret = -EINVAL;
            goto err;
        }
    }

    SGX_DBG(DBG_D, "respond_agent_request: status %d, plen %d\n", status, plen);

    return 0;

err:
    INLINE_SYSCALL(close, 1, agent_cfd);
    agent_cfd = -1;
    return -1;
}
