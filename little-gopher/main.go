package main

/*
#include <stdlib.h>
#include <stdio.h>

int * sum(int a, int b) {
	int * result = malloc(sizeof(int));
	*result = a+b;
	return result;
}

int string_to_buffer(const char *string, char *out) {
    int n;
    n = sprintf(out, "I am a C-string in C-land. %s", string);
    return n;
}

*/
//import "C"

import (
	"fmt"
	"unsafe"
)
func main() {
	y := 1+2
	x := unsafe.Pointer(&y)//C.sum(1, 2)
	fmt.Printf(string(*(*uint32)(x)))//fmt.Printf(string(int(*x)))
	//defer C.free(unsafe.Pointer(x))

	//simple_string := C.CString("I am a C-string in Go-land!")
	//ptr := C.malloc(C.sizeof_char * 1024)
	//defer C.free(unsafe.Pointer(ptr))
	//defer C.free(unsafe.Pointer(simple_string))
	
	//size := C.string_to_buffer(simple_string, (*C.char)(ptr))
	//result := C.GoBytes(ptr, size)
	//fmt.Println(string(result))

}
	
