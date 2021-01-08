package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"unsafe"
)

const PLUGIN_NAME string = "jevt"
const PLUGIN_DESCRIPTION = "implements extracting arbitrary fields from inputs formatted as JSON"

const VERBOSE bool = false
const NEXT_BUF_LEN uint32 = 65535
const OUT_BUF_LEN uint32 = 4096

///////////////////////////////////////////////////////////////////////////////
// framework constants

const SCAP_SUCCESS int32 = 0
const SCAP_FAILURE int32 = 1
const SCAP_TIMEOUT int32 = -1

const TYPE_SOURCE_PLUGIN uint32 = 1
const TYPE_EXTRACTOR_PLUGIN uint32 = 2

type getFieldsEntry struct {
	Type string `json:"type"`
	Name string `json:"name"`
	Desc string `json:"desc"`
}

///////////////////////////////////////////////////////////////////////////////

type pluginContext struct {
	outBufRaw unsafe.Pointer
	outBuf    []byte
	outBufLen int
}

var gCtx pluginContext
var gLastError string = ""

//export plugin_get_type
func plugin_get_type() uint32 {
	return TYPE_EXTRACTOR_PLUGIN
}

//export plugin_init
func plugin_init(config *C.char, rc *int32) *C.char {
	if !VERBOSE {
		log.SetOutput(ioutil.Discard)
	}

	log.Printf("[%s] plugin_init\n", PLUGIN_NAME)
	log.Printf("config string:\n%s\n", C.GoString(config))

	//
	// Allocate the state struct
	//
	gCtx = pluginContext{
		outBufLen: int(OUT_BUF_LEN),
	}

	//
	// We need a piece of memory to share data with the C code, which we'll use as
	// storage for plugin_extract_str()
	// We allocate this buffer with malloc so we can easily share it with the C code.
	// At the same time, we map it as a byte[] array to make it easy to deal with it
	// on the go side.
	//
	gCtx.outBufRaw = C.malloc(C.size_t(OUT_BUF_LEN))
	gCtx.outBuf = (*[1 << 30]byte)(unsafe.Pointer(gCtx.outBufRaw))[:int(gCtx.outBufLen):int(gCtx.outBufLen)]

	*rc = SCAP_SUCCESS

	//
	// XXX plugin peristent state is currently global, so we don't return it to the engine.
	// The reason is that cgo doesn't let us pass go structs to C code, even if they will
	// be treated as fully opaque.
	// We will need to fix this
	//
	return nil
}

//export plugin_get_last_error
func plugin_get_last_error() *C.char {
	log.Printf("[%s] plugin_get_last_error\n", PLUGIN_NAME)
	return C.CString(gLastError)
}

//export plugin_destroy
func plugin_destroy(context *byte) {
	log.Printf("[%s] plugin_destroy\n", PLUGIN_NAME)

	//
	// Release the memory buffers
	//
	C.free(gCtx.outBufRaw)
}

//export plugin_get_name
func plugin_get_name() *C.char {
	log.Printf("[%s] plugin_get_name\n", PLUGIN_NAME)
	return C.CString(PLUGIN_NAME)
}

//export plugin_get_description
func plugin_get_description() *C.char {
	log.Printf("[%s] plugin_get_description\n", PLUGIN_NAME)
	return C.CString(PLUGIN_DESCRIPTION)
}

const FIELD_ID_VALUE uint32 = 0
const FIELD_ID_MSG uint32 = 1

//export plugin_get_fields
func plugin_get_fields() *C.char {
	log.Printf("[%s] plugin_get_fields\n", PLUGIN_NAME)
	flds := []getFieldsEntry{
		{Type: "string", Name: "jevt.value", Desc: "allows to extract a value from a JSON-encoded input. Syntax is jevt.value[/x/y/z], where x,y and z are levels in the JSON hierarchy."},
		{Type: "string", Name: "jevt.json", Desc: "the full json message as a text string."},
	}

	b, err := json.Marshal(&flds)
	if err != nil {
		gLastError = err.Error()
		return nil
	}

	return C.CString(string(b))
}

//export plugin_extract_str
func plugin_extract_str(evtnum uint64, id uint32, arg *C.char, data *C.char, datalen uint32) *C.char {
	var line string
	var jdata map[string]interface{}

	//
	// Decode the json
	//
	err := json.Unmarshal([]byte(C.GoString(data)), &jdata)
	if err != nil {
		//
		// Not a json file. We return nil to indicate that the field is not
		// present.
		//
		return nil
	}

	switch id {
	case FIELD_ID_VALUE:
		sarg := C.GoString(arg)
		if sarg[0] == '/' {
			sarg = sarg[1:]
		}
		hc := strings.Split(sarg, "/")
		for j := 0; j < len(hc)-1; j++ {
			key := hc[j]
			if jdata[key] != nil {
				jdata = jdata[key].(map[string]interface{})
			} else {
				return nil
			}
		}
		val := jdata[hc[len(hc)-1]]
		if val == nil {
			return nil
		}
		line = fmt.Sprintf("%v", val)
	case FIELD_ID_MSG:
		js, _ := json.MarshalIndent(&jdata, "", "  ")
		line = string(js)
		line += "\n"
	default:
		line = "<NA>"
	}

	line += "\x00"

	//
	// Copy the the line into the event buffer
	//
	copy(gCtx.outBuf[:], line)

	return (*C.char)(gCtx.outBufRaw)
}

func main() {
}
