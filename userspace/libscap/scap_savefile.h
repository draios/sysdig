/*
Copyright (C) 2013-2014 Draios inc.

This file is part of sysdig.

sysdig is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

sysdig is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sysdig.  If not, see <http://www.gnu.org/licenses/>.
*/

// Force struct alignment
#if defined _MSC_VER
#pragma pack(push)
#pragma pack(1)
#elif defined __sun
#pragma pack(1)
#else
#pragma pack(push, 1)
#endif

///////////////////////////////////////////////////////////////////////////////
// GENERIC BLOCK
///////////////////////////////////////////////////////////////////////////////
typedef struct _block_header
{
	uint32_t block_type;
	uint32_t block_total_length; // Block length, including this header and the trailing 32bits block length.
}block_header;

///////////////////////////////////////////////////////////////////////////////
// SECTION HEADER BLOCK
///////////////////////////////////////////////////////////////////////////////
// Block type of the section header block
#define SHB_BLOCK_TYPE	0x0A0D0D0A    /*\r\n\n\r*/
// Magic of the section header block
// Used to recognize if a section is in host byte order or not.
#define SHB_MAGIC		0x1A2B3C4D
// Major version of the file format supported by this library.
// Must be increased only when if the new version of the software
// is not able anymore to read older captures
#define CURRENT_MAJOR_VERSION	1
// Minor version of the file format supported by this library.
// Must be increased every time we change the capture format
// (e.g. most of the changes in the event table, like adding
// a syscall)
#define CURRENT_MINOR_VERSION	2

typedef struct _section_header_block
{
	uint32_t byte_order_magic;
	uint16_t major_version;
	uint16_t minor_version;
	uint64_t section_length;
}section_header_block;

///////////////////////////////////////////////////////////////////////////////
// MACHINE INFO BLOCK
///////////////////////////////////////////////////////////////////////////////
#define MI_BLOCK_TYPE			0x201
#define MI_BLOCK_TYPE_INT		0x8002ABCD	// This is the unofficial number used before the
											// library release. We'll keep him for a while for
											// backward compatibility

///////////////////////////////////////////////////////////////////////////////
// PROCESS LIST BLOCK
///////////////////////////////////////////////////////////////////////////////
#define PL_BLOCK_TYPE_V1		0x202
#define PL_BLOCK_TYPE_V1_INT	0x8000ABCD	// This is the unofficial number used before the
											// library release. We'll keep him for a while for
											// backward compatibility

#define PL_BLOCK_TYPE_V2		0x207
#define PL_BLOCK_TYPE_V2_INT	0x8013ABCD	// This is the unofficial number used before the
											// library release. We'll keep him for a while for
											// backward compatibility

#define PL_BLOCK_TYPE_V3		0x209
#define PL_BLOCK_TYPE_V3_INT	0x8014ABCD	// This is the unofficial number used before the
											// library release. We'll keep him for a while for
											// backward compatibility

#define PL_BLOCK_TYPE_V4		0x210

#define PL_BLOCK_TYPE_V5		0x211

#define PL_BLOCK_TYPE_V6		0x212

#define PL_BLOCK_TYPE_V7		0x213

#define PL_BLOCK_TYPE_V8		0x214

#define PL_BLOCK_TYPE_V9		0x215

///////////////////////////////////////////////////////////////////////////////
// FD LIST BLOCK
///////////////////////////////////////////////////////////////////////////////
#define FDL_BLOCK_TYPE			0x203
#define FDL_BLOCK_TYPE_INT		0x8001ABCD	// This is the unofficial number used before the
											// library release. We'll keep him for a while for
											// backward compatibility
#define FDL_BLOCK_TYPE_V2		0x218

///////////////////////////////////////////////////////////////////////////////
// EVENT BLOCK
///////////////////////////////////////////////////////////////////////////////
#define EV_BLOCK_TYPE			0x204
#define EV_BLOCK_TYPE_INT		0x8010ABCD	// This is the unofficial number used before the
											// library release. We'll keep him for a while for
											// backward compatibility
#define EV_BLOCK_TYPE_V2		0x216

///////////////////////////////////////////////////////////////////////////////
// INTERFACE LIST BLOCK
///////////////////////////////////////////////////////////////////////////////
#define IL_BLOCK_TYPE			0x205
#define IL_BLOCK_TYPE_INT		0x8011ABCD	// This is the unofficial number used before the
											// library release. We'll keep him for a while for
											// backward compatibility

///////////////////////////////////////////////////////////////////////////////
// USER LIST BLOCK
///////////////////////////////////////////////////////////////////////////////
#define UL_BLOCK_TYPE			0x206
#define UL_BLOCK_TYPE_INT		0x8012ABCD	// This is the unofficial number used before the
											// library release. We'll keep him for a while for
											// backward compatibility

///////////////////////////////////////////////////////////////////////////////
// EVENT BLOCK WITH FLAGS
///////////////////////////////////////////////////////////////////////////////
#define EVF_BLOCK_TYPE		0x208

#define EVF_BLOCK_TYPE_V2	0x217

#if defined __sun
#pragma pack()
#else
#pragma pack(pop)
#endif
