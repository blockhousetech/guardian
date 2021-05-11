#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_ecall_function_t {
	int* ms_v;
} ms_ecall_function_t;

static sgx_status_t SGX_CDECL sgx_ecall_function(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_function_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_function_t* ms = SGX_CAST(ms_ecall_function_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_v = ms->ms_v;
	size_t _len_v = sizeof(int);
	int* _in_v = NULL;

	// CHECK_UNIQUE_POINTER(_tmp_v, _len_v);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	// if (_tmp_v != NULL && _len_v != 0) {
	// 	if ( _len_v % sizeof(*_tmp_v) != 0)
	// 	{
	// 		status = SGX_ERROR_INVALID_PARAMETER;
	// 		goto err;
	// 	}
	// 	_in_v = (int*)malloc(_len_v);
	// 	if (_in_v == NULL) {
	// 		status = SGX_ERROR_OUT_OF_MEMORY;
	// 		goto err;
	// 	}

	// 	if (memcpy_s(_in_v, _len_v, _tmp_v, _len_v)) {
	// 		status = SGX_ERROR_UNEXPECTED;
	// 		goto err;
	// 	}

	// }

	ecall_function(_tmp_v);

err:
	if (_in_v) free(_in_v);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[1];
} g_ecall_table = {
	1,
	{
		{(void*)(uintptr_t)sgx_ecall_function, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


