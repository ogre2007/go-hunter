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
	"strings"
	"bufio"
	"reflect"
    "math/rand"
)


func StringToBytes(s string) [] byte {
    strHeader :=(*reflect.StringHeader)(unsafe.Pointer(&s))
    bytesHeader:=reflect.SliceHeader{
        Data: strHeader.Data,
        Cap: strHeader.Len,
        Len: strHeader.Len,
    }
    return *(*[]byte)(unsafe.Pointer(&bytesHeader))
}

func GetBytes() []byte {
	reader := bufio.NewReader(strings.NewReader("hello!123"))
	s, _ := reader.ReadString('\n')
	out := StringToBytes(s)
	fmt.Printf("GetBytes: %s\n", out)

	return out
}

func UnsafeDefinition() unsafe.Pointer {
    var x unsafe.Pointer
    y := rand.Intn(100)
    x = unsafe.Pointer(&y)
    if (UnsafeCall()) {
        fmt.Println("bingo!")
    }
    return x
}

func UnsafeParameter(x unsafe.Pointer) int {
    y := rand.Intn(100)
    if (UnsafeCall()) {
        fmt.Println("bingo!")
    }
    return *(*int)(x) + y 
}

func UnsafeAssignment() unsafe.Pointer {
    y := rand.Intn(100)
    x := unsafe.Pointer(&y)
    if (UnsafeCall()) {
        fmt.Println("bingo!")
    }
    return x
}

func UnsafeCall() bool {
    x := rand.Intn(100)
    UnsafeParameter(unsafe.Pointer(&x))
    return true
}

func main() {
    /*
	y := 1+2
	x := unsafe.Pointer(&y)
    z := rand.Intn(100)
    xxy := unsafe.Pointer(&z)
    xvalue := *(*uint32)(x)
    zvalue := *(*uint32)(xxy)
	fmt.Printf("%d",xvalue + zvalue)
    */
    x := UnsafeDefinition()
    _ = x
    y := UnsafeParameter(x)
    _ = y
    z := UnsafeAssignment()
    _ = z
    v := UnsafeCall()
    _ = v
    
    
	bytesResult := GetBytes()
	fmt.Printf("main: %s\n", bytesResult)

	//defer C.free(unsafe.Pointer(x))

	//simple_string := C.CString("I am a C-string in Go-land!")
	//ptr := C.malloc(C.sizeof_char * 1024)
	//defer C.free(unsafe.Pointer(ptr))
	//defer C.free(unsafe.Pointer(simple_string))
	
	//size := C.string_to_buffer(simple_string, (*C.char)(ptr))
	//result := C.GoBytes(ptr, size)
	//fmt.Println(string(result))

}
	
