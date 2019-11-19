#ifndef SGX_AGENT_H
#define SGX_AGENT_H

/* The definition of agent request type */
#define AGENT_REQ_TYPE_ECHO                 0
#define AGENT_REQ_TYPE_RA                   1
#define AGENT_REQ_TYPE_MAX                  2

/* The definition of agent response status */
#define AGENT_RES_STAT_SUCCESS              0
#define AGENT_RES_STAT_UNKNOWN              1
#define AGENT_RES_STAT_INVALID_PAYLOAD      2
#define AGENT_RES_STAT_INVALID_REQUEST_TYPE 3
#define AGENT_RES_STAT_NO_QUOTE             4
#define AGENT_RES_STAT_INVALID_QUOTE        5
#define AGENT_RES_STAT_INVALID_QUOTE_SIG    6
#define AGENT_RES_STAT_INVALID_QE_REPORT    7
#define AGENT_RES_STAT_NO_REPORT            8
#define AGENT_RES_STAT_INVALID_REPORT       9

int init_agent_thread (void);

struct sgx_agent_request {
    uint32_t type;
    union {
        struct {
            uint64_t val;
        } echo;        

        struct {
            uint8_t nonce[16];
        } ra;
    } payload;
};

struct sgx_agent_payload_vector {
    void* p;
    size_t plen;
    bool freeup;
};

struct sgx_agent_response {
    uint32_t status;
    size_t pvec_nr;
    struct sgx_agent_payload_vector pvec[8];
};

int init_graphene_agent(void);
int retrieve_agent_request(uint32_t* type, void** payload, uint32_t* payload_len);
int respond_agent_request(uint32_t status, void* p, uint32_t plen);

#endif /* SGX_AGENT_H */
