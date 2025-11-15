//go:build (linux || darwin) && cgo

package dnsengine

/*
#cgo LDFLAGS: -L${SRCDIR}/../../rust/dns_engine/target/release -ldns_engine
#include <stdlib.h>

char* dns_engine_echo(const char* input);
void dns_engine_free(char* s);
*/
import "C"
import "unsafe"

func Echo(msg string) string {
	cstr := C.CString(msg)
	defer C.free(unsafe.Pointer(cstr))

	out := C.dns_engine_echo(cstr)
	if out == nil {
		return ""
	}
	defer C.dns_engine_free(out)

	return C.GoString(out)
}
