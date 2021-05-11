#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_function_t {
	int* ms_v;
} ms_ecall_function_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	0,
	{ NULL },
};
sgx_status_t ecall_function(sgx_enclave_id_t eid, int* v)
{
	sgx_status_t status;
	ms_ecall_function_t ms;
	ms.ms_v = v;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

