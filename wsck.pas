unit wsck;



interface

uses  Windows,sysutils;

const
    WSADESCRIPTION_LEN     =   256;
  WSASYS_STATUS_LEN      =   128;

type
// Some Winsock 2 type declarations
  u_char  = Char;
  u_short = Word;
  u_int   = Integer;
  u_long  = Longint;

  SunB = packed record
    s_b1, s_b2, s_b3, s_b4: u_char;
  end;
  SunW = packed record
    s_w1, s_w2: u_short;
  end;
  in_addr = record
    case integer of
      0: (S_un_b: SunB);
      1: (S_un_w: SunW);
      2: (S_addr: u_long);
  end;
  TInAddr = in_addr;
  Sockaddr_in = record
    case Integer of
      0: (sin_family: u_short;
          sin_port: u_short;
          sin_addr: TInAddr;
          sin_zero: array[0..7] of Char);
      1: (sa_family: u_short;
          sa_data: array[0..13] of Char)
  end;
  TSockAddr = Sockaddr_in;
  TSocket = u_int;
  TPacketBuffer = Array[0..4096-1] of byte;

  PWSAData = ^TWSAData;
  WSAData = record // !!! also WSDATA
    wVersion: Word;
    wHighVersion: Word;
    szDescription: array[0..WSADESCRIPTION_LEN] of Char;
    szSystemStatus: array[0..WSASYS_STATUS_LEN] of Char;
    iMaxSockets: Word;
    iMaxUdpDg: Word;
    lpVendorInfo: PChar;
  end;
  TWSAData = WSAData;

    PHostEnt = ^THostEnt;
  {$EXTERNALSYM hostent}
  hostent = record
    h_name: PChar;
    h_aliases: ^PChar;
    h_addrtype: Smallint;
    h_length: Smallint;
    case Byte of
      0: (h_addr_list: ^PChar);
      1: (h_addr: ^PChar)
  end;
  THostEnt = hostent;

   PServEnt = ^TServEnt;
  {$EXTERNALSYM servent}
  servent = record
    s_name: PChar;
    s_aliases: ^PChar;
    s_port: Word;
    s_proto: PChar;
  end;
  TServEnt = servent;

  PProtoEnt = ^TProtoEnt;
  {$EXTERNALSYM protoent}
  protoent = record
    p_name: PChar;
    p_aliases: ^Pchar;
    p_proto: Smallint;
  end;
  TProtoEnt = protoent;

  type sockaddr_gen = packed record
    AddressIn: sockaddr_in;
    filler: packed array[0..7] of char;
  end;

 INTERFACE_INFO = packed record
    iiFlags: u_long; // ????? ??????????
    iiAddress: sockaddr_gen; // ????? ??????????
    iiBroadcastAddress: sockaddr_gen; // Broadcast ?????
    iiNetmask: sockaddr_gen; // ????? ???????
  end;

const
MAX_CHAR = $10000;
  //MAX_CHAR = 2048;
 //https://msdn.microsoft.com/en-us/library/windows/desktop/ee309610(v=vs.85).aspx
 SIO_RCVALL = $98000001;
 RCVALL_OFF = 0;
 RCVALL_ON = 1;
 RCVALL_SOCKETLEVELONLY = 2;
 RCVALL_IPLEVEL = 3;
 SIO_GET_INTERFACE_LIST = $4004747F;
  IFF_UP = $00000001;
  IFF_BROADCAST = $00000002;
  IFF_LOOPBACK = $00000004;
  IFF_POINTTOPOINT = $00000008;
  IFF_MULTICAST = $00000010;

  SOL_SOCKET      = $ffff;
  SO_SNDBUF       = $1001;
  SO_RCVBUF = $1002;
  SO_SNDTIMEO     = $1005;
  SO_RCVTIMEO     = $1006;          { receive timeout }
  SO_BROADCAST = $20;

   SOCK_STREAM     = 1;               { stream socket }
  SOCK_DGRAM      = 2;               { datagram socket }
  SOCK_RAW        = 3;               { raw-protocol interface }
  SOCK_RDM        = 4;               { reliably-delivered message }
  SOCK_SEQPACKET  = 5;               { sequenced packet stream }

    AF_INET         = 2;               // internetwork: UDP, TCP, etc.
  IP_HDRINCL      = 2;               // IP Header Include

  INVALID_SOCKET = TSocket(NOT(0));
  SOCKET_ERROR                  = -1;
  FD_READ         = $01;
  FD_WRITE        = $02;
  FD_OOB          = $04;
  FD_ACCEPT       = $08;
  FD_CONNECT      = $10;
  FD_CLOSE        = $20;

  ICMP_ECHO                = 8  ;  (* echo service *)
  ICMP_REDIRECT                = 5  ;
  f_packet_no: word = 0;

   FIONBIO = $8004667E; //2147772030



function getservbyport(port: Integer; proto: PChar): PServEnt; stdcall;external 'ws2_32.dll';
function bind(s: TSocket; var addr: TSockAddr; namelen: Integer): Integer; stdcall;external 'ws2_32.dll';
function gethostbyaddr(addr: Pointer; len, Struct: Integer): PHostEnt; stdcall;external 'ws2_32.dll';
function gethostbyname(name: PChar): PHostEnt; stdcall;external 'ws2_32.dll';
function gethostname(name: PChar; len: Integer): Integer; stdcall;external 'ws2_32.dll';
function inet_ntoa(inaddr: TInAddr): PChar; stdcall;external 'ws2_32.dll';
function ntohs(netshort: u_short): u_short; stdcall;external 'ws2_32.dll';
function recv(s: TSocket; var Buf; len, flags: Integer): Integer; stdcall;external 'ws2_32.dll';
function closesocket(s: TSocket): Integer; stdcall;external 'ws2_32.dll';
function socket(af, Struct, protocol: Integer): TSocket; stdcall;external 'ws2_32.dll';
function connect(s: TSocket; var name: TSockAddr; namelen: Integer): Integer; stdcall;external 'ws2_32.dll';
function sendto(s: TSocket; var Buf; len, flags: Integer; var addrto: TSockAddr;
  tolen: Integer): Integer; stdcall;external 'ws2_32.dll';
function setsockopt(s: TSocket; level, optname: Integer; optval: PChar;
  optlen: Integer): Integer; stdcall;external 'ws2_32.dll';
function getsockopt(s: TSocket; level, optname: Integer; optval: PChar;
  optlen: Integer): Integer; stdcall;external 'ws2_32.dll';
function inet_addr(cp: PChar): u_long; stdcall; external 'ws2_32.dll'; {PInAddr;}  { TInAddr }
function ntohl(netlong: u_long): u_long; stdcall;external 'ws2_32.dll';
function htonl(hostlong: u_long): u_long; stdcall;external 'ws2_32.dll';
function htons(hostshort: u_short): u_short; stdcall;external 'ws2_32.dll';
FUNCTION ioctlsocket(
  S:       TSocket;
  Cmd:     Longword;
  VAR Arg: u_long{Longword}
): Integer;stdcall;external 'ws2_32.dll';

function WSAGetLastError: Integer; stdcall;external 'ws2_32.dll';
function WSAStartup(wVersionRequired: word; var WSData: TWSAData): Integer; stdcall;external 'ws2_32.dll';
function WSACleanup: Integer; stdcall;external 'ws2_32.dll';
Function WSAIoctl(s: Tsocket;
  dwIoControlCode: dword;
  lpvInBuffer: pointer;
  cbInBuffer: DWORD;
  lpvOUTBuffer: pointer;
  cbOUTBuffer: dword;
  lpcbBytesReturned: LPDWORD;
  lpOverlapped: pointer;
  lpCompletionROUTINE: pointer): integer; stdcall; external 'ws2_32.dll';
function WSAAsyncSelect(s: TSocket; HWindow: HWND; wMsg: u_int; lEvent: Longint): Integer; stdcall; external 'ws2_32.dll';
//function WSASocketA( af, iType, protocol : Integer; lpProtocolInfo : LPWSAProtocol_InfoA; g : GROUP; dwFlags : DWORD ): TSocket; stdcall;external 'ws2_32.dll';
//function WSASocketW( af, iType, protocol : Integer; lpProtocolInfo : LPWSAProtocol_InfoW; g : GROUP; dwFlags : DWORD ): TSocket; stdcall;external 'ws2_32.dll';
//function WSASocket( af, iType, protocol : Integer; lpProtocolInfo : LPWSAProtocol_Info; g : GROUP; dwFlags : DWORD ): TSocket; stdcall;external 'ws2_32.dll';
{
function WSASocketA( af, iType, protocol : Integer; lpProtocolInfo : integer; g : integer; dwFlags : DWORD ): TSocket; stdcall;external 'ws2_32.dll';
function WSASocketW( af, iType, protocol : Integer; lpProtocolInfo : integer; g : integer; dwFlags : DWORD ): TSocket; stdcall;external 'ws2_32.dll';
function WSASocket( af, iType, protocol : Integer; lpProtocolInfo : integer; g : integer; dwFlags : DWORD ): TSocket; stdcall;external 'ws2_32.dll';
}



implementation


end.
