package olm

/*
#cgo LDFLAGS: -L/usr/local/lib/libolm.so -lolm
#include <olm/olm.h>
#include <stdlib.h>
*/
import "C"

// Session an olm session
type Session struct {
	ptr *C.struct_OlmSession
}
