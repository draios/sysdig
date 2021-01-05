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
		evtBufLen: int(NEXT_BUF_LEN),
		outBufLen: int(OUT_BUF_LEN),
		//	cloudTrailFilesDir: "/home/loris/git/cloud-connector/test/cloudtrail",
		//	cloudTrailFilesDir: "c:\\windump\\GitHub\\cloud-connector\\test\\cloudtrail",
		curFileNum: 0,
	}

	//
	// We need two different pieces of memory to share data with the C code:
	// - a buffer that contains the events that we create and send to the engine
	//   through next()
	// - storage for functions like plugin_event_to_string and plugin_extract_str,
	//   so that their results can be shared without allocations or data copies.
	// We allocate these buffers with malloc so we can easily share them with the C code.
	// At the same time, we map them as byte[] arrays to make it easy to deal with them
	// on the go side.
	//
	g_ctx.evtBufRaw = C.malloc(C.size_t(NEXT_BUF_LEN))
	g_ctx.evtBuf = (*[1 << 30]byte)(unsafe.Pointer(g_ctx.evtBufRaw))[:int(g_ctx.evtBufLen):int(g_ctx.evtBufLen)]

	g_ctx.outBufRaw = C.malloc(C.size_t(OUT_BUF_LEN))
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

const FIELD_ID_JEVT uint32 = 0
const FIELD_ID_CLOUDTRAIL_SRC uint32 = 1
const FIELD_ID_CLOUDTRAIL_NAME uint32 = 2
const FIELD_ID_CLOUDTRAIL_USER uint32 = 3
const FIELD_ID_CLOUDTRAIL_REGION uint32 = 4

//export plugin_get_fields
func plugin_get_fields() *C.char {
	log.Printf("[%s] plugin_get_fields\n", PLUGIN_NAME)
	flds := []get_fields_entry{
		{Type: "string", Name: "jevt.value", Desc: "allows to extract a value from a JSON-encoded input. Syntax is jevt.value[/x/y/z], where x,y and z are levels in the JSON hierarchy."},
		{Type: "string", Name: "cloudtrail.src", Desc: "the source of the cloudtrail event (eventSource in the json, without the '.amazonaws.com' trailer)."},
		{Type: "string", Name: "cloudtrail.name", Desc: "the name of the cloudtrail event (eventName in the json)."},
		{Type: "string", Name: "cloudtrail.user", Desc: "the user of the cloudtrail event (userIdentity.userName in the json)."},
		{Type: "string", Name: "cloudtrail.region", Desc: "the region of the cloudtrail event (awsRegion in the json)."},
	}

	b, err := json.Marshal(&flds)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	return C.CString(string(b))
}

//export plugin_open
func plugin_open(plg_state *C.char, params *C.char, rc *int32) *C.char {
	log.Printf("[%s] plugin_open\n", PLUGIN_NAME)

	*rc = SCAP_SUCCESS

	g_ctx.cloudTrailFilesDir = C.GoString(params)

	if len(g_ctx.cloudTrailFilesDir) == 0 {
		g_lastError = "cloudtrail_file plugin error: missing input directory argument"
		*rc = SCAP_FAILURE
		return nil
	}

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
		g_lastError = "cloudtrail_file plugin error: no json files found in " + g_ctx.cloudTrailFilesDir
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
		var user string = "<NA>"
		if jdata["userIdentity"] != nil {
			re := jdata["userIdentity"].(map[string]interface{})
			if re["userName"] != nil {
				user = fmt.Sprintf("%s", re["userName"])
			}
		}

		src := fmt.Sprintf("%s", jdata["eventSource"])

		if len(src) > len(".amazonaws.com") {
			srctrailer := src[len(src)-len(".amazonaws.com"):]
			if srctrailer == ".amazonaws.com" {
				src = src[0 : len(src)-len(".amazonaws.com")]
			}
		}

		line = fmt.Sprintf("[cloudtrail] src:%s name:%s user:%s reg:%s",
			src,
			jdata["eventName"],
			user,
			jdata["awsRegion"])
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

//export plugin_extract_str
func plugin_extract_str(evtnum uint64, id uint32, arg *C.char, data *C.char, datalen uint32) *C.char {
	//	log.Printf("[%s] plugin_extract_str\n", PLUGIN_NAME)

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
	case FIELD_ID_JEVT:
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
	case FIELD_ID_CLOUDTRAIL_SRC:
		line = fmt.Sprintf("%s", jdata["eventSource"])

		if len(line) > len(".amazonaws.com") {
			srctrailer := line[len(line)-len(".amazonaws.com"):]
			if srctrailer == ".amazonaws.com" {
				line = line[0 : len(line)-len(".amazonaws.com")]
			}
		}
	case FIELD_ID_CLOUDTRAIL_NAME:
		line = fmt.Sprintf("%s", jdata["eventName"])
	case FIELD_ID_CLOUDTRAIL_USER:
		if jdata["userIdentity"] == nil {
			return nil
		}
		re := jdata["userIdentity"].(map[string]interface{})
		if re["userName"] == nil {
			return nil
		}
		line = fmt.Sprintf("%s", re["userName"])
	case FIELD_ID_CLOUDTRAIL_REGION:
		line = fmt.Sprintf("%s", jdata["awsRegion"])
	default:
		line = "<NA>"
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
