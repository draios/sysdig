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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

const PLUGIN_ID uint32 = 2
const PLUGIN_NAME string = "cloudtrail_file"

const VERBOSE bool = false
const NEXT_BUF_LEN uint32 = 65535
const OUT_BUF_LEN uint32 = 4096

const SCAP_SUCCESS int32 = 0
const SCAP_FAILURE int32 = 1
const SCAP_TIMEOUT int32 = -1

type get_fields_entry struct {
	Type string `json:"type"`
	Name string `json:"name"`
	Desc string `json:"desc"`
}

type plugin_context struct {
	evtBufRaw          unsafe.Pointer
	evtBuf             []byte
	evtBufLen          int
	outBufRaw          unsafe.Pointer
	outBuf             []byte
	outBufLen          int
	cloudTrailFilesDir string
	files              []string
	curFileNum         uint32
}

var g_ctx plugin_context
var g_lastError string = ""

//export plugin_init
func plugin_init(config *C.char, rc *int32) *C.char {
	if !VERBOSE {
		log.SetOutput(ioutil.Discard)
	}

	log.Printf("[cloudtrail_file] plugin_init\n")
	log.Printf("config string:\n%s\n", C.GoString(config))

	//
	// Allocate the state struct
	//
	g_ctx = plugin_context{
		evtBufLen:          int(NEXT_BUF_LEN),
		outBufLen:          int(OUT_BUF_LEN),
//		cloudTrailFilesDir: "/home/loris/git/cloud-connector/test/cloudtrail",
		cloudTrailFilesDir: "c:\\windump\\GitHub\\cloud-connector\\test\\cloudtrail",
		curFileNum:         0,
	}

	//
	// We need two different pieces of memory to share data with the C code:
	// - a buffer that contains the events that we create and send to the engine
	//   through next()
	// - storage for functions like plugin_event_to_string and plugin_extract_as_string,
	//   so that their results can be shared without allocations or data copies.
	// We allocate these buffers with malloc so we can easily share them with the C code.
	// At the same time, we map them as byte[] arrays to make it easy to deal with them
	// on the go side.
	//
	g_ctx.evtBufRaw = C.malloc(C.ulonglong(NEXT_BUF_LEN))
	g_ctx.evtBuf = (*[1 << 30]byte)(unsafe.Pointer(g_ctx.evtBufRaw))[:int(g_ctx.evtBufLen):int(g_ctx.evtBufLen)]

	g_ctx.outBufRaw = C.malloc(C.ulonglong(OUT_BUF_LEN))
	g_ctx.outBuf = (*[1 << 30]byte)(unsafe.Pointer(g_ctx.outBufRaw))[:int(g_ctx.outBufLen):int(g_ctx.outBufLen)]

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
	return C.CString(g_lastError)
}

//export plugin_destroy
func plugin_destroy(context *byte) {
	log.Printf("[%s] plugin_destroy\n", PLUGIN_NAME)

	//
	// Release the memory buffers
	//
	C.free(g_ctx.evtBufRaw)
	C.free(g_ctx.outBufRaw)
}

//export plugin_get_id
func plugin_get_id() uint32 {
	log.Printf("[%s] plugin_get_id\n", PLUGIN_NAME)
	return PLUGIN_ID
}

//export plugin_get_name
func plugin_get_name() *C.char {
	//	log.Printf("[%s] plugin_get_name\n", PLUGIN_NAME)
	return C.CString(PLUGIN_NAME)
}

//export plugin_get_description
func plugin_get_description() *C.char {
	log.Printf("[%s] plugin_get_description\n", PLUGIN_NAME)
	return C.CString("reads cloudtrail JSON data saved to file in the directory specified in the settings")
}

//export plugin_get_fields
func plugin_get_fields() *C.char {
	log.Printf("[%s] plugin_get_fields\n", PLUGIN_NAME)
	flds := []get_fields_entry{
		{Type: "string", Name: "jevt.value", Desc: "allows to extract a value from a JSON-encoded input. Syntax is jevt.value[/x/y/z], where x,y and z are levels in the JSON hierarchy."},
	}

	b, err := json.Marshal(&flds)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	return C.CString(string(b))
}

//export plugin_open
func plugin_open(plg_state *C.char, rc *int32) *C.char {
	log.Printf("[%s] plugin_open\n", PLUGIN_NAME)

	*rc = SCAP_SUCCESS

	log.Printf("[%s] scanning directory %s\n", PLUGIN_NAME, g_ctx.cloudTrailFilesDir)

	err := filepath.Walk(g_ctx.cloudTrailFilesDir, func(path string, info os.FileInfo, err error) error {
		if info != nil && info.IsDir() {
			return nil
		}

		if filepath.Ext(path) != ".json" {
			return nil
		}

		g_ctx.files = append(g_ctx.files, path)
		return nil
	})
	if err != nil {
		g_lastError = err.Error()
		*rc = SCAP_FAILURE
	}
	if len(g_ctx.files) == 0 {
		g_lastError = "no json files found in " + g_ctx.cloudTrailFilesDir
		*rc = SCAP_FAILURE
	}

	log.Printf("[%s] found %d json files\n", PLUGIN_NAME, len(g_ctx.files))

	//
	// XXX open state is currently global, so we don't return it to the engine.
	// The reason is that cgo doesn't let us pass go structs to C code, even if they will
	// be treated as fully opaque.
	// We will need to fix this
	//
	return nil
}

//export plugin_close
func plugin_close(plg_state *C.char, open_state *C.char) {
	log.Printf("[%s] plugin_close\n", PLUGIN_NAME)
}

//export plugin_next
func plugin_next(plg_state *C.char, open_state *C.char, data **C.char, datalen *uint32) int32 {
	//	log.Printf("[%s] plugin_next\n", PLUGIN_NAME)

	//
	// Open the next file and bring its content into memeory
	//
	if g_ctx.curFileNum >= uint32(len(g_ctx.files)) {
		time.Sleep(100 * time.Millisecond)
		return SCAP_TIMEOUT
	}

	file := g_ctx.files[g_ctx.curFileNum]
//fmt.Println("**", file)
	str, err := ioutil.ReadFile(file)
	if err != nil {
		g_lastError = err.Error()
		return SCAP_FAILURE
	}

	g_ctx.curFileNum++

	if len(str) > len(g_ctx.evtBuf) {
		g_lastError = fmt.Sprintf("cloudwatch message too long: %d, max 65535 supported", len(str))
		return SCAP_FAILURE
	}

	//
	// NULL-terminate the json data string, so that C will like it
	//
	str = append(str, 0)

	//
	// Copy the json string into the event buffer
	//
	copy(g_ctx.evtBuf[:], str)

	//
	// Ready to return the event
	//
	*data = (*C.char)(g_ctx.evtBufRaw)
	*datalen = uint32(len(str))
	return SCAP_SUCCESS
}

//export plugin_event_to_string
func plugin_event_to_string(data *C.char, datalen uint32) *C.char {
	//	log.Printf("[%s] plugin_event_to_string\n", PLUGIN_NAME)
	var line string
	var jdata map[string]interface{}

	err := json.Unmarshal([]byte(C.GoString(data)), &jdata)
	if err != nil {
		g_lastError = err.Error()
		line = "<invalid JSON: " + err.Error() + ">"
	} else {
		var rv string = "BOH"
		if jdata["responseElements"] != nil {
			re := jdata["responseElements"].(map[string]interface{})
			if re["_return"] != nil {
				rv = strconv.FormatBool(re["_return"].(bool))
			}
		}

		line = fmt.Sprintf("%s Res:%s Region:%s", jdata["eventName"], rv, jdata["awsRegion"])
	}

	//
	// NULL-terminate the json data string, so that C will like it
	//
	line += "\x00"

	//
	// Copy the the line into the event buffer
	//
	copy(g_ctx.outBuf[:], line)

	return (*C.char)(g_ctx.outBufRaw)
}

//export plugin_extract_as_string
func plugin_extract_as_string(evtnum uint64, id uint32, arg *C.char, data *C.char, datalen uint32) *C.char {
	//	log.Printf("[%s] plugin_extract_as_string\n", PLUGIN_NAME)

	var line string
	var jdata map[string]interface{}

	if(id != 0) {
		line = "<NA>"
	} else {
		err := json.Unmarshal([]byte(C.GoString(data)), &jdata)
		if err != nil {
			return nil
		} else {
			sarg := C.GoString(arg)
			if sarg[0] == '/' {
				sarg = sarg[1:]
			}
			hc := strings.Split(sarg, "/")
			for j := 0; j < len(hc) - 1; j++ {
				key := hc[j]
				if jdata[key] != nil {
					jdata = jdata[key].(map[string]interface{})
				} else {
					return nil
				}
			}
			val := jdata[hc[len(hc) - 1]]
			if val == nil {
				return nil
			}
			line = fmt.Sprintf("%v", val)
		}
	}

	line += "\x00"

	//
	// Copy the the line into the event buffer
	//
	copy(g_ctx.outBuf[:], line)

	return (*C.char)(g_ctx.outBufRaw)
}

func main() {
}
