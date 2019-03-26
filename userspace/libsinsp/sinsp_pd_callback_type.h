#pragma once

//
// Protocol decoder callback type
//
typedef enum sinsp_pd_callback_type
{
	CT_OPEN,
	CT_CONNECT,
	CT_READ,
	CT_WRITE,
	CT_TUPLE_CHANGE,
}sinsp_pd_callback_type;
