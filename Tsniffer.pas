{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

unit Tsniffer;

interface

//{$IFDEF WIN64}
//function GetWindowLongPtr; external user32 name 'GetWindowLongPtrW';
//function GetWindowLongPtrA; external user32 name 'GetWindowLongPtrA';
//function GetWindowLongPtrW; external user32 name 'GetWindowLongPtrW';
//{$ELSE}
//function GetWindowLongPtr; external user32 name 'GetWindowLongW';
//function GetWindowLongPtrA; external user32 name 'GetWindowLongA';
//function GetWindowLongPtrW; external user32 name 'GetWindowLongW';
//{$ENDIF}

//we could use jwawinsock2, or a mini wsck or the original winsock2.pas from Alex konshin
//winsock.pas from delphi and fpc is actually linked to wsock32.dll
uses windows,sysutils,classes,winsock;

const
GWLP_USERDATA = (-21);

WM_ASYNCSELECT = WM_USER + 0;
IPPROTO_IP     =   0;
IPPROTO_ICMP   =   1;
IPPROTO_TCP    =   6;
IPPROTO_UDP    =  17;
IPPROTO_RAW    =  255;
//
MAX_CHAR = $10000;
IP_HDRINCL      = 2;
RCVALL_ON = 1;
RCVALL_IPLEVEL = 3;
SIO_RCVALL = $98000001;
IOC_VENDOR    = $18000000;
//SIO_RCVALL                          = (IOC_IN or IOC_VENDOR or 1);
SIO_GET_INTERFACE_LIST = $4004747F;
IFF_UP = $00000001;
IFF_LOOPBACK = $00000004;

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

//


type

  TRawSniffer= class
  private
  //FThread : mysnifferThread;
  RawSocket: TSocket;
  FWndHandle:hwnd;
  procedure WMASyncSelect(var msg: TMessage);
  function WindowProc(HWindow: HWnd; Message: UINT; WParam: WPARAM; LParam: LPARAM): Longint;stdcall;
  public
  //FWndHandle:hwnd;
  promisc:boolean;
  str_ip:string;
  OnPacket : Procedure(Data:pointer;recvbytes:Word;ptime:pchar) of Object;
  OnError : Procedure(msg:string) of Object;
  constructor Create;
  Destructor Destroy;override;
  procedure opensocket_;
  procedure closesocket_;
  class function EnumInterfaces: tstringlist; {$IFDEF FPC}static;{$ENDIF}
  protected

end;


implementation


Function WSAIoctl(s: Tsocket;
  dwIoControlCode: dword;
  lpvInBuffer: pointer;
  cbInBuffer: DWORD;
  lpvOUTBuffer: pointer;
  cbOUTBuffer: dword;
  lpcbBytesReturned: LPDWORD;
  lpOverlapped: pointer;
  lpCompletionROUTINE: pointer): integer; stdcall; external 'ws2_32.dll';

function dummy(hWnd: HWND; Msg: UINT; WPARAM: WPARAM; LPARAM: LPARAM): LRESULT; stdcall;
var
  vData: Pointer;
begin
  vData := Pointer(GetWindowLongA(hWnd, GWLP_USERDATA)); //GetWindowLongPtr
  Result := TRawSniffer(VData).WindowProc(hWnd, Msg, WPARAM, LPARAM);
end;


// event handler
procedure TRawSniffer.WMASyncSelect(var msg: TMessage);
var ws_rcv:integer;
     buf: Array[0..MAX_CHAR] Of char;
     p:pointer;

begin
  case LoWord(msg.lParam) of
    FD_READ:
    begin
      ws_rcv:=0;
      //if Assigned(FDataAvailable) then  FDataAvailable(Self,msg.wParam);
      //rawsocket = msg.wparam
      ws_rcv := recv(msg.wparam, buf, sizeof(buf), 0);
      //if (ws_rcv<=0) {or (ws_rcv>1514)} then exit;
      p:=@buf[0];
      onpacket(p,ws_rcv,pchar(formatdatetime('hh:nn:ss:zzz', now)));
      p:=nil;
    end;
  end; //case
end;

{ Queue message handling }
function TRawSniffer.WindowProc(HWindow: HWnd; Message: UINT; WParam: WPARAM; LParam: LPARAM): Longint;stdcall;
  var
       ws_rcv:integer;
     buf: Array[0..MAX_CHAR] Of char;
  begin

    case message of
    WM_CLOSE:
    begin
      PostQuitMessage(0);
      Result := 0;
    end;
    WM_USER:
    begin
       ws_rcv := recv(wparam, buf, sizeof(buf), 0);  ;
       //writeln(inttostr(message)+' recv:'+inttostr(ws_rcv));
       onpacket(@buf[0],ws_rcv,pchar(formatdatetime('hh:nn:ss:zzz', now)));
      Result := 1;
    end
    else Result:=DefWindowProc(HWindow,Message,WParam,LParam);
    end; //case

  end;

destructor TRawSniffer.Destroy;
begin
  closesocket_;
  inherited;

end;

constructor TRawSniffer.Create;
var
     wc: WNDCLASS;
begin
{$ifdef FPC}
//AllocateHWnd not available under FPC :(
wc.style         := 0;
wc.lpfnWndProc   := @dummy ; //tsniffer method
wc.cbClsExtra    := 0;
wc.cbWndExtra    := 0;
wc.hInstance     := HInstance;
wc.hIcon         := 0;
wc.hCursor       := LoadCursor(0, IDC_ARROW);
wc.hbrBackground := HBRUSH(COLOR_WINDOW + 1);
wc.lpszMenuName  := nil;
wc.lpszClassName := 'snif';
if Windows.RegisterClass(wc) = 0 then raise Exception.Create('RegisterClass failed: ' + SysErrorMessage(GetLastError));
FWndHandle :=CreateWindow(wc.lpszClassName, wc.lpszClassName, 0, 0, 0, 100, 100, 0, 0, HInstance, nil);;
if FWndHandle=0 then raise exception.create('FWndHandle=0');
//Sets the user data associated with the window.
//This data is intended for use by the application that created the window. Its value is initially zero.
SetWindowlongPtr(FWndHandle, GWLP_USERDATA, LONG_PTR(self));
//to redefine wndproc ... not needed here
//SetWindowLong(FWndHandle, GWL_WNDPROC, LongInt(method_ptr));
{$else}
  FWndHandle := AllocateHWnd(WMASyncSelect);
{$endif}

//or we could use createvent and waitforsingleobjet on a separate thread?

end;

procedure TRawSniffer.closesocket_;
begin
WSAASyncSelect(RawSocket ,FWndHandle,WM_ASYNCSELECT,0);
WSACleanUp;
{$ifdef FPC}

{$else}
    if FWndHandle<>0 then DeallocateHWnd(FWndHandle);
{$endif}
end;

procedure TRawSniffer.opensocket_;
var
  WSAData: TWSAData;
  opt, result: Integer;
  sa: TSockAddrin;
  //arg:longword;
  arg:integer;
  b:boolean;


begin

  WSAStartup(MakeWord(2, 2), WSAData);

  Try
    RawSocket := socket(AF_INET, SOCK_raw , IPPROTO_ip );
    If RawSocket = INVALID_SOCKET Then Raise Exception.Create('INVALID_SOCKET');

    //setsockopt before bind OK?
    //https://docs.microsoft.com/en-us/windows/desktop/api/winsock/nf-winsock-setsockopt
    opt := 5000;
    result := setsockopt(RawSocket, SOL_SOCKET, SO_RCVTIMEO, pchar(@opt), sizeof(opt));
    If result = SOCKET_ERROR Then Raise Exception.Create('SetSocket failed:'+inttostr(WSAGetLastError ));

    //WSAEFAULT - 10014
    //WSAEADDRNOTAVAIL 10049
    //not needed as we are not sending? opt is int? bool? does not work with winsock 1
    {
    opt:=1;
    result:=setsockopt(RawSocket, IPPROTO_IP, IP_HDRINCL, pchar(@opt), sizeof(opt));
    If result = SOCKET_ERROR Then Raise Exception.Create('SetSocket failed:'+inttostr(WSAGetLastError ));
    }

    sa.sin_family := AF_INET;
    sa.sin_port := htons(0);
    //sa.sin_addr.s_addr := ip^;
    sa.sin_addr.S_addr :=inet_Addr(PansiChar(ansistring(str_ip)));

    // ***************** BIND *******************
    result := bind(RawSocket, sa, sizeof(sa));
    If result = SOCKET_ERROR Then Raise Exception.Create('bind failed');
    // ***************** BIND *******************

    //set this option after BIND
    //more buffer to hold data remember : 1 frame is about 1500 bytes
    //at 1 gbits/sec, you better be fast between two recv
    opt:=8192*8;
    result:=setsockopt(RawSocket, SOL_SOCKET, SO_RCVBUF, pchar(@opt), sizeof(opt));
    If result = SOCKET_ERROR Then Raise Exception.Create('setsockopt failed');

    //https://msdn.microsoft.com/en-us/library/windows/desktop/ee309610(v=vs.85).aspx
    if promisc=true then arg:=RCVALL_ON else arg:=RCVALL_IPLEVEL;
    result:= ioctlsocket(RawSocket, SIO_RCVALL , arg);
    If result = SOCKET_ERROR Then Raise Exception.Create('ioctlsocket SIO_RCVALL failed:'+inttostr(WSAGetLastError));

    // arg:=1; // 1= nonblocking 0= blocking
    //IOCtlSocket(RawSocket,FIONBIO,arg);

//handle has been taken care of in the create method
result := WSAASyncSelect(RawSocket,FWndHandle,
WM_ASYNCSELECT,
FD_READ    ); //or FD_CONNECT or FD_WRITE or FD_ACCEPT
if result <> 0 then
   begin
   raise exception.create('WSAASyncSelect socket error:'+inttostr(WSAGetLastError));
   closesocket(RawSocket);
   WSACleanup;
   end;

    //AnalysisDataPacket;
  Except
  on e:exception do
    begin
    closesocket(RawSocket);
    WSACleanup;
    if assigned(onerror) then onerror(e.message);
    end;
  End; //try

end;
//*****************************************************************************
class function TRawSniffer.EnumInterfaces: tstringlist;
var s: TSocket;
  WSAD: WSADATA;
  NumInterfaces: Integer;
  BytesReturned, SetFlags: u_long;
  pAddrInet: SOCKADDR_IN;
  pAddrString: PCHAR;
  PtrA: pointer;
  Buffer: array[0..20] of INTERFACE_INFO;
  ret,i: Integer;
  sl:tstringlist;
begin
  result := nil;


  ret:=WSAStartup(makeword(2,2), WSAD);


  s := Socket(AF_INET, SOCK_STREAM, 0);
  if (s = INVALID_SOCKET) then exit;

  try
    PtrA := @bytesReturned;
    if (WSAIoCtl(s, SIO_GET_INTERFACE_LIST, nil, 0, @Buffer, 1024, PtrA, nil, nil) <> SOCKET_ERROR)
      then
      begin

      NumInterfaces := BytesReturned div SizeOf(INTERFACE_INFO);
      sl:=tstringlist.create;
      for i := 0 to NumInterfaces - 1 do
      begin
        pAddrInet := Buffer[i].iiAddress.addressIn;
        pAddrString := inet_ntoa(pAddrInet.sin_addr);


        SetFlags := Buffer[i].iiFlags;

        //we should exclude down interface
        //127.0.0.1 is supported by raw sockets
        if ((SetFlags and IFF_UP) = IFF_UP) {and ((SetFlags and IFF_LOOPBACK)<>IFF_LOOPBACK)} then sl.Add (pAddrString );

      end;
     result:=sl;
    end;
  except
    result := nil;
  end;
//
// ????????? ??????
//
  CloseSocket(s);
  if ret=0 then WSACleanUp;
end;
//**********************************************************************

end.
