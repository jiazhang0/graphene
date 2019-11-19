#include "pal_linux.h"
#include "pal_security.h"
#include "pal_internal.h"
#include <pal_debug.h>
#include <api.h>

#include "enclave_ocalls.h"
#include "sgx_attest.h"
#include "sgx_agent.h"

PAL_HANDLE agent_thread;

static uint32_t agent_handle_request(struct sgx_agent_request* req, struct sgx_agent_response* res)
{
    sgx_quote_t* quote;
    sgx_report_t qe_report;
    size_t quote_len;
    uint32_t plen;
    int ret;

    switch (req->type) {
    case AGENT_REQ_TYPE_RA:
        quote = NULL;
        quote_len = 0;
        ret = sgx_get_quote(&req->payload.ra.nonce, &quote, &quote_len, &qe_report);
        if (ret < 0 || !quote || !quote_len) {
            res->status = AGENT_RES_STAT_NO_QUOTE;
            return 0;
        }

        if (quote_len <= sizeof(sgx_quote_t)) {
            SGX_DBG(DBG_D, "The length of quote (%ld-byte) retrieved is too short\n", quote_len);
            res->status = AGENT_RES_STAT_INVALID_QUOTE;
            return 0;
        }

        SGX_DBG(DBG_D, "Quote header %ld-byte, signature %d-byte, total quote %ld-byte\n",
                sizeof(sgx_quote_t), quote->sig_len, quote_len);

        if (sizeof(sgx_quote_t) + quote->sig_len > quote_len) {
            SGX_DBG(DBG_D, "Invalid length of signature (%d-byte) in quote\n", quote->sig_len);
            res->status = AGENT_RES_STAT_INVALID_QUOTE_SIG;
            return 0;
        }

        ret = sgx_verify_report(&qe_report);
        if (ret < 0) {
            SGX_DBG(DBG_E, "Failed to verify QE report: %d\n", ret);
            res->status = AGENT_RES_STAT_INVALID_QE_REPORT;
            return 0;
        }

        __sgx_mem_aligned sgx_report_t report;
        __sgx_mem_aligned sgx_target_info_t targetinfo = pal_sec.aesm_targetinfo;
        ret = sgx_report(&targetinfo, (sgx_report_data_t*)&pal_enclave_state, &report);
        if (ret) {
            SGX_DBG(DBG_E, "Failed to get report for attestation\n");
            res->status = AGENT_RES_STAT_NO_REPORT;
            return 0;
        }

        //sgx_print_report((sgx_report_t*)&quote->report_body);
        //sgx_print_report(&report);

	if (memcmp(&quote->report_body, &report, sizeof(quote->report_body))) {
	    SGX_DBG(DBG_E, "Invalid report in quote\n");
            res->status = AGENT_RES_STAT_INVALID_REPORT;
            return 0;
	}

	/* Exclude the padding bytes at the tail of returned quote */
        plen = sizeof(sgx_quote_t) + quote->sig_len;
        res->pvec_nr = 1;
        res->pvec[0].p = quote;
        res->pvec[0].plen = plen;
        res->pvec[0].freeup = true;
        break;
    case AGENT_REQ_TYPE_ECHO:
        plen = sizeof(req->payload.echo.val);
        res->pvec_nr = 1;
        res->pvec[0].p = &req->payload.echo.val;
        res->pvec[0].plen = plen;
        break;
    default:
        res->status = AGENT_RES_STAT_UNKNOWN;
        return 0;
    }

    res->status = AGENT_RES_STAT_SUCCESS;

    return plen;
}

static int sgx_agent_run(void* args)
{
    __UNUSED(args);

    SGX_DBG(DBG_D, "Agent thread started\n");

    while (1) {
        struct sgx_agent_request req;
        int rv = ocall_retrieve_agent_request(&req);
        if (rv < 0) {
            SGX_DBG(DBG_E, "ocall_retrieve_agent_request error on %d\n", rv);
            continue;
        }

        struct sgx_agent_response res;
        memset(&res, 0, sizeof(res));
        uint32_t plen = agent_handle_request(&req, &res);

        rv = ocall_acknowledge_agent_response(&res, plen);
        if (rv < 0)
            SGX_DBG(DBG_E, "ocall_acknowledge_agent_response error on %d\n", rv);

        for (size_t i = 0; i < res.pvec_nr; ++i) {
            if (res.pvec[i].freeup)
                free(res.pvec[i].p); 
        }
    }

    SGX_DBG(DBG_I, "Agent thread exiting ...\n");

    DkThreadExit();
    /* Should never return */
    assert(0);

    return -PAL_ERROR_INVAL;
}

int init_agent_thread(void)
{
    agent_thread = DkThreadCreate(sgx_agent_run, NULL);

    return agent_thread ? 0 : -PAL_ERROR_INVAL;
}
