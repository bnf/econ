/*
    Copyright (C) SEIKO EPSON CORPORATION 2002-2003. All Rights Reserved.

    3-3-5, Owa, Suwa-shi Nagano-ken, 392-8502 Japan
    Phone: +81-266-52-3131

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Library General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Library General Public License for more details.

    You should have received a copy of the GNU Library General Public
    License aint with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/


#if !defined(__ECONPROTOCOL__)
#define __ECONPROTOCOL__

#include <stdint.h>

#define ECON_PORTNUMBER			3620	
#define ECON_MAGICNUM_SIZE		4		
#define ECON_IPADDRESS_SIZE		4		
#define ECON_UNIQINFO_LENGTH		6		
#define	ECON_PROJNAME_MAXLEN		32		
#define ECON_KEYWORD_MAXLEN		16		
#define ECON_ENCRYPTION_MAXLEN		8		


#ifdef LITTLE_ENDIAN_HOST

#define Swap16IfLE(s) \
	((CARD16) ((((s) & 0xff) << 8) | (((s) >> 8) & 0xff)))
#define Swap32IfLE(l) \
	((CARD32) ((((l) & 0xff000000) >> 24) | \
		   (((l) & 0x00ff0000) >> 8)  | \
		   (((l) & 0x0000ff00) << 8)  | \
		   (((l) & 0x000000ff) << 24)))

#else

#define Swap16IfLE(s) (s)
#define Swap32IfLE(l) (l)

#endif



#define ECON_MAGIC_NUMBER	"EEMP"		
#define ECON_PROTO_VERSION	"0100"		
#define ECON_PROTOVER_MAXLEN	4			


enum e_proj_state {
	E_PSTAT_NOUSE		=	1,			
	E_PSTAT_USING		=	2,			
	E_PSTAT_APPUSING	=	3			
};

enum _e_EmpCommand {
	E_CMD_EASYSEARCH	=	1,			
	E_CMD_IPSEARCH		=	2,			
	E_CMD_CLIENTINFO	=	3,			
	E_CMD_REQCONNECT	=	4,			
	E_CMD_CONNECTED		=	5,			
	E_CMD_REQRESTART	=	6,			
	E_CMD_FINISHRESTART	=	7,			
	E_CMD_DISCONCLIENT	=	8,			
	E_CMD_INTERRUPT		=	9,			
	E_CMD_KEEPALIVE		=	10,			

	E_CMD_SENDREQUESTS	=	12,			
	E_CMD_CLIENTERROR	=	13,			
	E_CMD_RESENDFULLSCRID	=	14,			
	E_CMD_DISPLAYWAIT	=	15,			
	E_CMD_SENDKEY		=	16          
};

enum _e_ProjType {
	e_ptype_IM_X		=	1,			
	e_ptype_IM_XP1		=	2,			
	e_pType_IM_XP4		=	3			
};

enum _e_SendReq {
	e_sendreq_OK		=	1,			
	e_sendreq_NG		=	2			
};


enum _e_Keyword {
	e_keyword_nouse		=	0,			
	e_keyword_use		=	1			
};



enum _e_Encryption {
	e_encrypt_nouse		=	0,			
	e_encrypt_use		=	1			
};



enum _e_Error {
	e_error_keyword		=	0			
};


typedef struct {
	uint8_t bitsPerPixel;		
	uint8_t depth;			
	uint8_t bigEndian;		
	uint8_t trueColour;		

	uint16_t redMax;			
	uint16_t greenMax;		
	uint16_t blueMax;			
	uint8_t redShift;			
	uint8_t greenShift;		
	uint8_t blueShift;		
	uint8_t pad1;
	uint16_t pad2;
} rfbPixelFormat;


typedef struct {
	uint16_t framebufferWidth;
	uint16_t framebufferHeight;
	rfbPixelFormat format;
	uint32_t nameLength;
} rfbServerInitMsg;


typedef struct {
	char projName[ECON_PROJNAME_MAXLEN];		
	uint8_t	projState;							
	uint8_t	useKeyword;							
	uint8_t	displayType;						
} e_command_clientinfo;


typedef struct {
	uint8_t	useEncryption;						
	uint8_t	EncPassword[ECON_ENCRYPTION_MAXLEN];
	uint8_t	subnetMask[ECON_IPADDRESS_SIZE];	
	uint8_t	gateAddress[ECON_IPADDRESS_SIZE];	
	rfbServerInitMsg vnesInitMsg;					
} e_command_reqconnect;


typedef struct {
	char projName[ECON_PROJNAME_MAXLEN];		
	uint8_t	projState;							
} e_command_connected;



typedef struct {
	uint8_t	errorNo;								
} e_command_clienterror;



typedef struct {
	uint32_t resendID;								
} e_command_resendfullscrid;



typedef struct {
	uint32_t keyID;                              
} e_command_sendkey;

typedef struct {
	uint16_t unknown_field1;
	uint16_t unknown_field2;
	uint16_t width;
	uint16_t height;
} e_command_cmd22;


struct econ_header{
	char magicnum[ECON_MAGICNUM_SIZE];		
	char version[ECON_PROTOVER_MAXLEN];		
	uint8_t IPaddress[ECON_IPADDRESS_SIZE];		
	uint32_t commandID;							
	uint32_t datasize;							
};

struct econ_command{
	uint8_t recordCount;				
	uint8_t implicit_padding[3];
	union e_commands {
		e_command_clientinfo clientinfo;	
		e_command_reqconnect reqconnect;	
		e_command_connected connected;		
		e_command_clienterror clienterror;	
		e_command_resendfullscrid resendid;	
		e_command_sendkey sendkey;        

		e_command_cmd22 cmd22;
	} command;
};

struct econ_record {
	uint8_t projUniqInfo[ECON_UNIQINFO_LENGTH];	
	uint8_t projKeyword[ECON_KEYWORD_MAXLEN];	
	uint8_t IPaddress[ECON_IPADDRESS_SIZE];		
};

#endif
