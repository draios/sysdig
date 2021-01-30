package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/valyala/fastjson"
)

const PLUGIN_ID uint32 = 2
const PLUGIN_NAME string = "cloudtrail"
const PLUGIN_DESCRIPTION = "reads cloudtrail JSON data saved to file in the directory specified in the settings"

const S3_DOWNLOAD_CONCURRENCY = 64
const VERBOSE bool = false
const NEXT_BUF_LEN uint32 = 65535
const OUT_BUF_LEN uint32 = 4096

///////////////////////////////////////////////////////////////////////////////
// framework constants

const SCAP_SUCCESS int32 = 0
const SCAP_FAILURE int32 = 1
const SCAP_TIMEOUT int32 = -1
const SCAP_EOF int32 = 6

const TYPE_SOURCE_PLUGIN uint32 = 1
const TYPE_EXTRACTOR_PLUGIN uint32 = 2

type getFieldsEntry struct {
	Type string `json:"type"`
	Name string `json:"name"`
	Desc string `json:"desc"`
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

///////////////////////////////////////////////////////////////////////////////

type fileInfo struct {
	name         string
	isCompressed bool
}

type s3State struct {
	bucket                string
	awsSvc                *s3.S3
	awsSess               *session.Session
	downloader            *s3manager.Downloader
	DownloadWg            sync.WaitGroup
	DownloadBufs          [][]byte
	lastDownloadedFileNum int
	nFilledBufs           int
	curBuf                int
}

type pluginContext struct {
	isS3               bool
	evtBufRaw          unsafe.Pointer
	evtBuf             []byte
	evtBufLen          int
	outBufRaw          unsafe.Pointer
	outBuf             []byte
	outBufLen          int
	cloudTrailFilesDir string
	files              []fileInfo
	curFileNum         uint32
	evtJsonList        []interface{}
	evtJsonListPos     int
	jparser            fastjson.Parser
	jdata              *fastjson.Value
	jdataEvtnum        uint64 // The event number jdata refers to. Used to know when we can skip the unmarshaling.
	s3                 s3State
}

var gCtx pluginContext
var gLastError string = ""

//export plugin_get_type
func plugin_get_type() uint32 {
	return TYPE_SOURCE_PLUGIN
}

func receiver(rc *int32) {
	for true {
		atomic.CompareAndSwapInt32(rc,
			1, // old
			2) // new
	}
}

//export plugin_init
func plugin_init(config *C.char, rc *int32) *C.char {
	//	go receiver(rc)

	if !VERBOSE {
		log.SetOutput(ioutil.Discard)
	}

	log.Printf("[%s] plugin_init\n", PLUGIN_NAME)
	log.Printf("config string:\n%s\n", C.GoString(config))

	//
	// Allocate the state struct
	//
	gCtx = pluginContext{
		evtBufLen:      int(NEXT_BUF_LEN),
		outBufLen:      int(OUT_BUF_LEN),
		curFileNum:     0,
		evtJsonListPos: 0,
		jdataEvtnum:    math.MaxUint64,
	}

	gCtx.s3.lastDownloadedFileNum = 0
	gCtx.s3.nFilledBufs = 0
	gCtx.s3.curBuf = 0

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
	gCtx.evtBufRaw = C.malloc(C.size_t(NEXT_BUF_LEN))
	gCtx.evtBuf = (*[1 << 30]byte)(unsafe.Pointer(gCtx.evtBufRaw))[:int(gCtx.evtBufLen):int(gCtx.evtBufLen)]

	gCtx.outBufRaw = C.malloc(C.size_t(OUT_BUF_LEN))
	gCtx.outBuf = (*[1 << 30]byte)(unsafe.Pointer(gCtx.outBufRaw))[:int(gCtx.outBufLen):int(gCtx.outBufLen)]

	//
	// We create an array of download buffers that will be used to concurrently
	// download files from s3
	//
	gCtx.s3.DownloadBufs = make([][]byte, S3_DOWNLOAD_CONCURRENCY)

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
	C.free(gCtx.evtBufRaw)
	C.free(gCtx.outBufRaw)
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
	return C.CString(PLUGIN_DESCRIPTION)
}

const FIELD_ID_CLOUDTRAIL_ID uint32 = 0
const FIELD_ID_CLOUDTRAIL_TIME uint32 = 1
const FIELD_ID_CLOUDTRAIL_SRC uint32 = 2
const FIELD_ID_CLOUDTRAIL_NAME uint32 = 3
const FIELD_ID_CLOUDTRAIL_USER uint32 = 4
const FIELD_ID_CLOUDTRAIL_REGION uint32 = 5
const FIELD_ID_CLOUDTRAIL_SRCIP uint32 = 6
const FIELD_ID_CLOUDTRAIL_USERAGENT uint32 = 7
const FIELD_ID_CLOUDTRAIL_INFO uint32 = 8
const FIELD_ID_S3_BUCKET uint32 = 9
const FIELD_ID_S3_KEY uint32 = 10
const FIELD_ID_S3_HOST uint32 = 11
const FIELD_ID_S3_URI uint32 = 12
const FIELD_ID_S3_BYTES uint32 = 13
const FIELD_ID_S3_BYTES_IN uint32 = 14
const FIELD_ID_S3_BYTES_OUT uint32 = 15
const FIELD_ID_S3_CNT_GET uint32 = 16
const FIELD_ID_S3_CNT_PUT uint32 = 17
const FIELD_ID_S3_CNT_OTHER uint32 = 18
const FIELD_ID_EC2_NAME uint32 = 19

//export plugin_get_fields
func plugin_get_fields() *C.char {
	log.Printf("[%s] plugin_get_fields\n", PLUGIN_NAME)
	flds := []getFieldsEntry{
		{Type: "string", Name: "ct.id", Desc: "the unique ID of the cloudtrail event (eventID in the json)."},
		{Type: "string", Name: "ct.time", Desc: "the timestamp of the cloudtrail event (eventTime in the json)."},
		{Type: "string", Name: "ct.src", Desc: "the source of the cloudtrail event (eventSource in the json, without the '.amazonaws.com' trailer)."},
		{Type: "string", Name: "ct.name", Desc: "the name of the cloudtrail event (eventName in the json)."},
		{Type: "string", Name: "ct.user", Desc: "the user of the cloudtrail event (userIdentity.userName in the json)."},
		{Type: "string", Name: "ct.region", Desc: "the region of the cloudtrail event (awsRegion in the json)."},
		{Type: "string", Name: "ct.srcip", Desc: "the IP address generating the event (sourceIPAddress in the json)."},
		{Type: "string", Name: "ct.useragent", Desc: "the user agent generating the event (userAgent in the json)."},
		{Type: "string", Name: "ct.info", Desc: "summary information about the event. This varies depending on the event type and, for some events, it contains event-specific details."},
		{Type: "string", Name: "s3.bucket", Desc: "the bucket name for s3 events."},
		{Type: "string", Name: "s3.key", Desc: "the key name for s3 events."},
		{Type: "string", Name: "s3.host", Desc: "the host name for s3 events."},
		{Type: "string", Name: "s3.uri", Desc: "the s3 URI (s3://<bucket>/<key>) for s3 events."},
		{Type: "uint64", Name: "s3.bytes", Desc: "the size of an s3 download or upload, in bytes."},
		{Type: "uint64", Name: "s3.bytes.in", Desc: "the size of an s3 upload, in bytes."},
		{Type: "uint64", Name: "s3.bytes.out", Desc: "the size of an s3 download, in bytes."},
		{Type: "uint64", Name: "s3.cnt.get", Desc: "the number of get operations. This field is 1 for GetObject events, 0 otherwise."},
		{Type: "uint64", Name: "s3.cnt.put", Desc: "the number of put operations. This field is 1 for PutObject events, 0 otherwise."},
		{Type: "uint64", Name: "s3.cnt.other", Desc: "the number of non I/O operations. This field is 0 for GetObject and PutObject events, 1 for all the other events."},
		{Type: "string", Name: "ec2.name", Desc: "the name of the ec2 instances, typically stored in the instance tags."},
	}

	b, err := json.Marshal(&flds)
	if err != nil {
		gLastError = err.Error()
		return nil
	}

	return C.CString(string(b))
}

func openLocal(plgState *C.char, params *C.char, rc *int32) *C.char {
	*rc = SCAP_SUCCESS

	gCtx.cloudTrailFilesDir = C.GoString(params)

	if len(gCtx.cloudTrailFilesDir) == 0 {
		gLastError = PLUGIN_NAME + " plugin error: missing input directory argument"
		*rc = SCAP_FAILURE
		return nil
	}

	log.Printf("[%s] scanning directory %s\n", PLUGIN_NAME, gCtx.cloudTrailFilesDir)

	err := filepath.Walk(gCtx.cloudTrailFilesDir, func(path string, info os.FileInfo, err error) error {
		if info != nil && info.IsDir() {
			return nil
		}

		isCompressed := strings.HasSuffix(path, ".json.gz")
		if filepath.Ext(path) != ".json" && !isCompressed {
			return nil
		}

		var fi fileInfo = fileInfo{name: path, isCompressed: isCompressed}
		gCtx.files = append(gCtx.files, fi)
		return nil
	})
	if err != nil {
		gLastError = err.Error()
		*rc = SCAP_FAILURE
	}
	if len(gCtx.files) == 0 {
		gLastError = PLUGIN_NAME + " plugin error: no json files found in " + gCtx.cloudTrailFilesDir
		*rc = SCAP_FAILURE
	}

	log.Printf("[%s] found %d json files\n", PLUGIN_NAME, len(gCtx.files))

	//
	// XXX open state is currently global, so we don't return it to the engine.
	// The reason is that cgo doesn't let us pass go structs to C code, even if they will
	// be treated as fully opaque.
	// We will need to fix this
	//
	return nil
}

func openS3(plgState *C.char, params *C.char, rc *int32) *C.char {
	*rc = SCAP_SUCCESS
	input := C.GoString(params)

	//
	// remove the initial "s3://"
	//
	input = input[5:]
	slashindex := strings.Index(input, "/")

	//
	// Extract the URL components
	//
	var prefix string
	if slashindex == -1 {
		gCtx.s3.bucket = input
		prefix = ""
	} else {
		gCtx.s3.bucket = input[:slashindex]
		prefix = input[slashindex+1:]
	}

	//
	// Fetch the list of keys
	//
	gCtx.s3.awsSess = session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	gCtx.s3.awsSvc = s3.New(gCtx.s3.awsSess)

	err := gCtx.s3.awsSvc.ListObjectsPages(&s3.ListObjectsInput{
		Bucket: &gCtx.s3.bucket,
		Prefix: &prefix,
	}, func(p *s3.ListObjectsOutput, last bool) (shouldContinue bool) {
		for _, obj := range p.Contents {
			//fmt.Printf("> %v %v\n", *obj.Size, *obj.Key)
			path := obj.Key
			isCompressed := strings.HasSuffix(*path, ".json.gz")
			if filepath.Ext(*path) != ".json" && !isCompressed {
				continue
			}

			var fi fileInfo = fileInfo{name: *path, isCompressed: true}
			gCtx.files = append(gCtx.files, fi)
		}
		return true
	})
	if err != nil {
		gLastError = PLUGIN_NAME + " plugin error: failed to list objects: " + err.Error()
		*rc = SCAP_FAILURE
	}

	gCtx.s3.downloader = s3manager.NewDownloader(gCtx.s3.awsSess)

	return nil
}

//export plugin_open
func plugin_open(plgState *C.char, params *C.char, rc *int32) *C.char {
	log.Printf("[%s] plugin_open\n", PLUGIN_NAME)

	input := C.GoString(params)

	if input[:5] == "s3://" {
		gCtx.isS3 = true
		return openS3(plgState, params, rc)
	} else {
		gCtx.isS3 = false
		return openLocal(plgState, params, rc)
	}
}

//export plugin_close
func plugin_close(plgState *C.char, openState *C.char) {
	log.Printf("[%s] plugin_close\n", PLUGIN_NAME)
}

var dlErrChan chan error

func s3Download(downloader *s3manager.Downloader, name string, dloadSlotNum int) {
	defer gCtx.s3.DownloadWg.Done()

	buff := &aws.WriteAtBuffer{}
	_, err := downloader.Download(buff,
		&s3.GetObjectInput{
			Bucket: &gCtx.s3.bucket,
			Key:    &name,
		})
	if err != nil {
		dlErrChan <- err
		return
	}

	gCtx.s3.DownloadBufs[dloadSlotNum] = buff.Bytes()
}

func readNextFileS3() ([]byte, error) {
	if gCtx.s3.curBuf < gCtx.s3.nFilledBufs {
		curBuf := gCtx.s3.curBuf
		gCtx.s3.curBuf++
		return gCtx.s3.DownloadBufs[curBuf], nil
	}

	dlErrChan = make(chan error, S3_DOWNLOAD_CONCURRENCY)
	k := gCtx.s3.lastDownloadedFileNum
	gCtx.s3.nFilledBufs = min(S3_DOWNLOAD_CONCURRENCY, len(gCtx.files)-k)
	for j, f := range gCtx.files[k : k+gCtx.s3.nFilledBufs] {
		gCtx.s3.DownloadWg.Add(1)
		go s3Download(gCtx.s3.downloader, f.name, j)
	}
	gCtx.s3.DownloadWg.Wait()

	select {
	case e := <-dlErrChan:
		return nil, e
	default:
	}

	gCtx.s3.lastDownloadedFileNum += S3_DOWNLOAD_CONCURRENCY

	gCtx.s3.curBuf = 1
	return gCtx.s3.DownloadBufs[0], nil
}

func readFileLocal(fileName string) ([]byte, error) {
	return ioutil.ReadFile(fileName)
}

//export plugin_next
func plugin_next(plgState *C.char, openState *C.char, data **C.char, datalen *uint32, ts *uint64) int32 {
	//	log.Printf("[%s] plugin_next\n", PLUGIN_NAME)
	var str []byte
	var err error
	var jdata map[string]interface{}

	//
	// Only open the next file once we're sure that the content of the previous one has been full consumed
	//
	if gCtx.evtJsonListPos == len(gCtx.evtJsonList) {
		//
		// Open the next file and bring its content into memeory
		//
		if gCtx.curFileNum >= uint32(len(gCtx.files)) {
			return SCAP_EOF
		}

		file := gCtx.files[gCtx.curFileNum]
		gCtx.curFileNum++

		if gCtx.isS3 {
			str, err = readNextFileS3()
		} else {
			str, err = readFileLocal(file.name)
		}
		if err != nil {
			gLastError = err.Error()
			return SCAP_FAILURE
		}

		//
		// The file can be gzipped. If it is, we unzip it.
		//
		if file.isCompressed {
			gr, err := gzip.NewReader(bytes.NewBuffer(str))
			defer gr.Close()
			zdata, err := ioutil.ReadAll(gr)
			if err != nil {
				return SCAP_TIMEOUT
			}
			str = zdata
		}

		//
		// Interpret the json to undestand the file format (single vs multiple
		// events) and extract the individual records.
		//
		err = json.Unmarshal(str, &jdata)
		if err != nil {
			return SCAP_TIMEOUT
		}

		if len(jdata) == 1 && jdata["Records"] != nil {
			gCtx.evtJsonList = jdata["Records"].([]interface{})
			gCtx.evtJsonListPos = 0
		}
	}

	//
	// Extract the next record
	//
	var cr map[string]interface{}
	if len(gCtx.evtJsonList) != 0 {
		cr = gCtx.evtJsonList[gCtx.evtJsonListPos].(map[string]interface{})
		gCtx.evtJsonListPos++
	} else {
		cr = jdata
	}

	//
	// Extract the timestamp
	//
	t1, err := time.Parse(
		time.RFC3339,
		fmt.Sprintf("%s", cr["eventTime"]))
	if err != nil {
		// gLastError = fmt.Sprintf("time in unknown format: %s, %v(%v)",
		// 	cr["eventTime"],
		// 	gCtx.evtJsonListPos,
		// 	len(gCtx.evtJsonList))
		//
		// We assume this is just some spurious data and we continue
		//
		return SCAP_TIMEOUT
	}
	*ts = uint64(t1.Unix()) * 1000000000

	ets := fmt.Sprintf("%s", cr["eventType"])
	if ets == "AwsCloudTrailInsight" {
		return SCAP_TIMEOUT
	}

	//
	// Re-convert the event into a cunsumable string.
	// Note: this is done so that the engine in the libraries can treat things
	// as portable strings, which helps supporting features like transparent
	// capture file support. It's a bit unfortunate that we have to do a sequence
	// of multiple marshalings/unmarshalings and it's definitely not the best in
	// terms of efficiency. We'll work on optimizing it if it becomes a problem.
	//
	str, err = json.Marshal(&cr)
	if err != nil {
		return SCAP_TIMEOUT
	}

	if len(str) > len(gCtx.evtBuf) {
		gLastError = fmt.Sprintf("cloudwatch message too long: %d, max 65535 supported", len(str))
		return SCAP_FAILURE
	}

	//
	// NULL-terminate the json data string, so that C will like it
	//
	str = append(str, 0)

	//
	// Copy the json string into the event buffer
	//
	copy(gCtx.evtBuf[:], str)

	//
	// Ready to return the event
	//
	*data = (*C.char)(gCtx.evtBufRaw)
	*datalen = uint32(len(str))
	return SCAP_SUCCESS
}

func getUser(jdata *fastjson.Value) string {
	jutype := jdata.GetStringBytes("userIdentity", "type")
	if jutype != nil {
		utype := string(jutype)

		switch utype {
		case "Root", "IAMUser":
			jun := jdata.GetStringBytes("userIdentity", "userName")
			if jun != nil {
				return string(jun)
			}
		case "AWSService":
			jun := jdata.GetStringBytes("userIdentity", "invokedBy")
			if jun != nil {
				return string(jun)
			}
		case "AssumedRole":
			jun := jdata.GetStringBytes("sessionContext", "sessionIssuer", "userName")
			if jun != nil {
				return string(jun)
			}
			return "AssumedRole"
		case "AWSAccount":
			return "AWSAccount"
		case "FederatedUser":
			return "FederatedUser"
		default:
			return "<unknown user type>"
		}
	}

	return "<NA>"
}

func getEvtInfo(jdata *fastjson.Value) string {
	var present bool
	var evtname string
	var info string

	present, evtname = getfieldStr(jdata, FIELD_ID_CLOUDTRAIL_NAME)
	if !present {
		return "<invalid cloudtrail event: eventName field missing>"
	}

	switch evtname {
	case "GetObject", "PutObject":
		present, uri := getfieldStr(jdata, FIELD_ID_S3_URI)
		if present {
			info = fmt.Sprintf("%s", uri)
		} else {
			info = "<URI missing>"
		}

	case "PutBucketPublicAccessBlock":
		info = ""
		jpac := jdata.GetObject("requestParameters", "PublicAccessBlockConfiguration")
		if jpac != nil {
			info += fmt.Sprintf("BlockPublicAcls:%v BlockPublicPolicy:%v IgnorePublicAcls:%v RestrictPublicBuckets:%v ",
				jdata.GetBool("BlockPublicAcls"),
				jdata.GetBool("BlockPublicPolicy"),
				jdata.GetBool("IgnorePublicAcls"),
				jdata.GetBool("RestrictPublicBuckets"),
			)
		}
	default:
		info = ""
	}

	return info
}

func getfieldStr(jdata *fastjson.Value, id uint32) (bool, string) {
	var res string

	switch id {
	case FIELD_ID_CLOUDTRAIL_ID:
		res = string(jdata.GetStringBytes("eventID"))
	case FIELD_ID_CLOUDTRAIL_TIME:
		res = string(jdata.GetStringBytes("eventTime"))
	case FIELD_ID_CLOUDTRAIL_SRC:
		res = string(jdata.GetStringBytes("eventSource"))

		if len(res) > len(".amazonaws.com") {
			srctrailer := res[len(res)-len(".amazonaws.com"):]
			if srctrailer == ".amazonaws.com" {
				res = res[0 : len(res)-len(".amazonaws.com")]
			}
		}
	case FIELD_ID_CLOUDTRAIL_NAME:
		res = string(jdata.GetStringBytes("eventName"))
	case FIELD_ID_CLOUDTRAIL_USER:
		res = getUser(jdata)
	case FIELD_ID_CLOUDTRAIL_REGION:
		res = string(jdata.GetStringBytes("awsRegion"))
	case FIELD_ID_CLOUDTRAIL_SRCIP:
		res = string(jdata.GetStringBytes("sourceIPAddress"))
	case FIELD_ID_CLOUDTRAIL_USERAGENT:
		res = string(jdata.GetStringBytes("userAgent"))
	case FIELD_ID_CLOUDTRAIL_INFO:
		res = getEvtInfo(jdata)
	case FIELD_ID_S3_BUCKET:
		val := jdata.GetStringBytes("requestParameters", "bucketName")
		if val == nil {
			return false, ""
		}
		res = string(val)
	case FIELD_ID_S3_KEY:
		val := jdata.GetStringBytes("requestParameters", "key")
		if val == nil {
			return false, ""
		}
		res = string(val)
	case FIELD_ID_S3_HOST:
		val := jdata.GetStringBytes("requestParameters", "Host")
		if val == nil {
			return false, ""
		}
		res = string(val)
	case FIELD_ID_S3_URI:
		sbucket := jdata.GetStringBytes("requestParameters", "bucketName")
		if sbucket == nil {
			return false, ""
		}
		skey := jdata.GetStringBytes("requestParameters", "key")
		if skey == nil {
			return false, ""
		}
		res = fmt.Sprintf("s3://%s/%s", sbucket, skey)
	case FIELD_ID_EC2_NAME:
		var iname string = ""
		jilist := jdata.GetArray("requestParameters", "tagSpecificationSet", "items")
		if jilist == nil {
			return false, ""
		}
		for _, item := range jilist {
			if string(item.GetStringBytes("resourceType")) != "instance" {
				continue
			}
			tlist := item.GetArray("tags")
			for _, tag := range tlist {
				key := string(tag.GetStringBytes("key"))
				if key == "Name" {
					iname = string(tag.GetStringBytes("value"))
					break
				}
			}
		}

		if iname == "" {
			return false, ""
		}
		res = iname
	default:
		return false, ""
	}

	return true, res
}

//export plugin_event_to_string
func plugin_event_to_string(data *C.char, datalen uint32) *C.char {
	//	log.Printf("[%s] plugin_event_to_string\n", PLUGIN_NAME)
	var line string
	var src string
	var user string
	var err error

	gCtx.jdata, err = gCtx.jparser.Parse(C.GoString(data))
	if err != nil {
		gLastError = err.Error()
		line = "<invalid JSON: " + err.Error() + ">"
	} else {
		src = string(gCtx.jdata.GetStringBytes("eventSource"))

		if len(src) > len(".amazonaws.com") {
			srctrailer := src[len(src)-len(".amazonaws.com"):]
			if srctrailer == ".amazonaws.com" {
				src = src[0 : len(src)-len(".amazonaws.com")]
			}
		}

		user = getUser(gCtx.jdata)
		if user != "" {
			user = " " + user
		}

		info := getEvtInfo(gCtx.jdata)

		line = fmt.Sprintf("%s%s %s %s %s",
			gCtx.jdata.GetStringBytes("awsRegion"),
			user,
			src,
			gCtx.jdata.GetStringBytes("eventName"),
			info,
		)
	}

	//
	// NULL-terminate the json data string, so that C will like it
	//
	line += "\x00"

	//
	// Copy the the line into the event buffer
	//
	copy(gCtx.outBuf[:], line)

	return (*C.char)(gCtx.outBufRaw)
}

//export plugin_extract_str
func plugin_extract_str(evtnum uint64, id uint32, arg *C.char, data *C.char, datalen uint32) *C.char {
	var res string
	var err error

	//
	// Decode the json, but only if we haven't done it yet for this event
	//
	if evtnum != gCtx.jdataEvtnum {
		gCtx.jdata, err = gCtx.jparser.Parse(C.GoString(data))
		if err != nil {
			//
			// Not a json file. We return nil to indicate that the field is not
			// present.
			//
			return nil
		}
		gCtx.jdataEvtnum = evtnum
	}

	present, val := getfieldStr(gCtx.jdata, id)
	if !present {
		return nil
	} else {
		res = val
	}

	res += "\x00"

	//
	// Copy the the result into the event buffer
	//
	copy(gCtx.outBuf[:], res)

	return (*C.char)(gCtx.outBufRaw)
}

//export plugin_extract_u64
func plugin_extract_u64(evtnum uint64, id uint32, arg *C.char, data *C.char, datalen uint32) uint64 {
	var err error

	//
	// Decode the json, but only if we haven't done it yet for this event
	//
	if evtnum != gCtx.jdataEvtnum {
		gCtx.jdata, err = gCtx.jparser.Parse(C.GoString(data))
		if err != nil {
			//
			// Not a json file. We return nil to indicate that the field is not
			// present.
			//
			return 0
		}
		gCtx.jdataEvtnum = evtnum
	}

	switch id {
	case FIELD_ID_S3_BYTES:
		var tot uint64 = 0
		in := gCtx.jdata.Get("additionalEventData", "bytesTransferredIn")
		if in != nil {
			tot = tot + in.GetUint64()
		}
		out := gCtx.jdata.Get("additionalEventData", "bytesTransferredOut")
		if out != nil {
			tot = tot + out.GetUint64()
		}
		return tot
	case FIELD_ID_S3_BYTES_IN:
		var tot uint64 = 0
		in := gCtx.jdata.Get("additionalEventData", "bytesTransferredIn")
		if in != nil {
			fmt.Printf("1> %v\n", evtnum)
			tot = tot + in.GetUint64()
		}
		return tot
	case FIELD_ID_S3_BYTES_OUT:
		var tot uint64 = 0
		out := gCtx.jdata.Get("additionalEventData", "bytesTransferredOut")
		if out != nil {
			tot = tot + out.GetUint64()
		}
		return tot
	case FIELD_ID_S3_CNT_GET:
		if string(gCtx.jdata.GetStringBytes("eventName")) == "GetObject" {
			return 1
		}
		return 0
	case FIELD_ID_S3_CNT_PUT:
		if string(gCtx.jdata.GetStringBytes("eventName")) == "PutObject" {
			return 1
		}
		return 0
	case FIELD_ID_S3_CNT_OTHER:
		ename := string(gCtx.jdata.GetStringBytes("eventName"))
		if ename == "GetObject" || ename == "PutObject" {
			return 0
		}
		return 1
	default:
		return 0
	}
}

func main() {
}
