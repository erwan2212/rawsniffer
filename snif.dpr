//https://docs.microsoft.com/en-us/windows/desktop/winsock/tcp-ip-raw-sockets-2
{$r uac.res}

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

program snif;
{$APPTYPE CONSOLE}
uses
  classes,
  windows,
  sysutils,
  winsock,
  firewall,
  Tsniffer in 'Tsniffer.pas',
  ipheader in 'ipheader.pas',
  pcaptools in 'pcaptools.pas';

type tobj= class(Tobject)
private
Procedure OnPacket(data:pointer;recvsize:word;ptime:pchar);
Procedure OnError(msg:string);
protected
public
end;



//function GetBestInterface(dwDestAddr: Cardinal; pdwBestIfIndex: PDWORD): DWORD; stdcall;external 'iphlpapi.dll';
//function SendARP (const DestIP, SrcIP: Cardinal; pMacAddr: pointer;var PhyAddrLen: ULONG): DWORD; stdcall;external 'iphlpapi.dll';

var
cpt:cardinal;
Msg: TMSG;
raw_sniffer:TRawSniffer ;
obj:tobj;
ip,filter_proto,filter_port:string;
interfaces:tstrings;
fromf:file;
cap:boolean=false;
error:boolean=false;
mac:array[0..5] of byte;
SendARP: function (const DestIP, SrcIP: dword; pMacAddr: pointer;PhyAddrLen: PULONG): DWORD; stdcall=nil;



procedure open_cap;
const DLT_EN10MB      =1;
begin
AssignFile(FromF, 'dump'+formatdatetime('hh-nn-ss-zzz', now)+'.cap');
Rewrite (FromF,1);
write_cap_header(fromf,DLT_EN10MB);
end;

procedure close_cap;
begin
closefile(fromf);
end;

procedure save_frame(len:integer;data:pointer;ptime:pchar);
var
buf:pchar;
begin

    if len>0 then
    begin
       //mode_raw : dont forget ethernet header !
       len:=len+14;
       buf:=allocmem(len); //allocmem=getmem+Initialize
       //ethernet header 14 bytes
       buf[12]:=#8;buf[13]:=#0;
       //we could fill in the mac addresses by resolving ip to mac...
       {
       if PIP_Header(data)^.ip_srcaddr=inet_Addr(PChar(ip)) then copymemory(@buf[6],@mac[0],6);
       if PIP_Header(data)^.ip_destaddr=inet_Addr(PChar(ip)) then copymemory(@buf[0],@mac[0],6);
       }
       copymemory(@buf[14],data,len-14);
       write_cap_packet(fromf,len,ptime,buf);
       FreeMem(buf,len);
    end; //if len>0 then

end;

Procedure Tobj.OnError(msg:string);
begin
writeln(msg);
error:=true;
PostMessage(0,0,0,0);  //trigger getmessage
end;

Procedure Tobj.OnPacket(data:pointer;recvsize:word;ptime:pchar);
Var
  parpheader:parp_header;
  pipheader: PIP_Header; // PIP_Header
  //ptcpheader:PTCP_Header;
  //pudpheader:PUDP_Header;
  pbuf: pchar;
  i: Integer;
  //str: String;
  //s: String;
  src_port,dest_port:word;
  str_time,str_prot,str_srcip,str_destip,str_len:string;
Begin
//sanitary checks
if data=nil then exit;
if (recvsize<=0) or (recvsize>1514) then exit;
//
src_port:=0;dest_port:=0;
str_prot:='';str_srcip:='';str_destip:='';
str_len:='';
//
    //ip
       pipheader := PIP_Header(data);

//on recupere nos valeurs
      str_time:=FormatDateTime('hh:nn:ss:zzz', now); //we should use ptime...
      str_len:=inttostr(ntohs(pipheader^.ip_totallength));
      str_srcip:=strpas(Inet_Ntoa(TInAddr(pipheader^.ip_srcaddr)));
      str_destip:=strpas(Inet_Ntoa(TInAddr(pipheader^.ip_destaddr)));

      For i := 0 To 8 Do
      If pipheader^.ip_protocol = IPPROTO[i].itype Then str_prot := IPPROTO[i].name;

      //tcp
      If pipheader^.ip_protocol=6 then
      begin
           {
           ptcpheader := PTCP_Header(@pipheader.data );
           src_port:=   ntohs(ptcpheader.src_portno ) ;
           dest_port:= ntohs(ptcpheader.dst_portno )  ;
           }
           src_port:=   ntohs(PTCP_Header(@pipheader^.data )^.src_portno ) ;
           dest_port:= ntohs(PTCP_Header(@pipheader^.data )^.dst_portno )  ;
      end;
      //udp
      If pipheader^.ip_protocol=17 then
      begin
           {
           pudpheader := PUDP_Header(@pipheader.data );
           src_port:=   ntohs(pudpheader.src_portno ) ;
           dest_port:= ntohs(pudpheader.dst_portno )  ;
           }
           src_port:=   ntohs(PUDP_Header(@pipheader^.data )^.src_portno ) ;
           dest_port:= ntohs(PUDP_Header(@pipheader^.data )^.dst_portno )  ;
      end;

      //data
      //getmem(pbuf, recvsize );
      //copymemory(pbuf, data, recvsize );

//if (filter <>'') and (lowercase(filter) =lowercase(str_prot))
if (filter_proto <>'') and (lowercase(str_prot)=lowercase(filter_proto)) then
   begin
   if filter_port =''
      then writeln(str_time+' '+str_prot+' '+str_srcip+':'+inttostr(src_port)+' '+str_destip+':'+inttostr(dest_port)+' '+str_len + ' Bytes');
   if (filter_port =inttostr(src_port)) or (filter_port =inttostr(dest_port))
      then writeln(str_time+' '+str_prot+' '+str_srcip+':'+inttostr(src_port)+' '+str_destip+':'+inttostr(dest_port)+' '+str_len + ' Bytes');
   end;

if filter_proto =''
  then writeln(str_time+' '+str_prot+' '+str_srcip+':'+inttostr(src_port)+' '+str_destip+':'+inttostr(dest_port)+' '+str_len + ' Bytes');

if cap=true then save_frame(strtoint(str_len ),pipheader,ptime); //ptime or str_time...
End;



begin
writeln('raw sniffer 0.2 by erwan2212@gmail.com');
writeln('snif [localip:x.x.x.x] [proto:udp|tcp|icmp] [port:1-65535] [catpure:0|1] [firewall:0|1]');
writeln('use * if you want to skip/ignore a parameter');
writeln('snif 127.0.0.1 tcp 80 1 will filter tcp:80 traffic on localhost and dump all traffic to dump.cap file');
writeln('snif 127.0.0.1 udp * 0 will filter udp traffic on localhost but not to file');
writeln('snif 192.168.1.144 * * 0 1 will dump all traffic to console and create a firewall exception to capture incoming traffic');

//try GetBestInterface(0,@dwindex);except end;

if (paramcount>=1) and (paramstr(1)<>'*') then ip:=paramstr(1)
  else
  begin
  //ip:=getlocalip;
  ////GetAdaptersInfo_(adapter);
  ////if length(adapter)>0 then for i:=low(adapter) to high(adapter) do if adapter[i].Index =inttostr(dwIndex) then strip:=adapter[i].AddressList[0];
  interfaces:=TRawSniffer.EnumInterfaces;
  for cpt:=0 to interfaces.Count -1 do writeln(inttostr(cpt)+':'+interfaces[cpt]);
  writeln('choose interface');
  readln(cpt);
  try ip:=interfaces[cpt];except exit; end;
  end;

//if (length(paramstr(1))=1) and (paramstr(1)<>'*') then ip:=TRawSniffer.EnumInterfaces[strtoint(paramstr(1))];

{
cpt:=6;
fillchar(mac,6,0);
@sendarp:=GetProcAddress(LoadLibraryA(PAnsiChar('iphlpapi.dll')),'SendARP'); //case sensitive !!!!
if @sendarp<>nil then SendARP (inet_Addr(PChar(ip)),0,@mac[0],@cpt) ;
}

if (paramcount>=2) and (paramstr(2)<>'*') then filter_proto:=paramstr(2);
if (paramcount>=3) and (paramstr(3)<>'*') then filter_port:=paramstr(3);
if (paramcount>=4) and (paramstr(4)='1') then cap:=true else cap:=false;

try
  if (paramcount>=5) and (paramstr(5)='1') then
  begin
  writeln('adding inbound firewall exception');
  AddFirewallExceptionNT6('snif',paramstr(0));
  end;
except
on e:exception do writeln('AddFirewallExceptionNT6 failed:'+e.message);
end;

raw_sniffer:=TRawSniffer.Create ;
raw_sniffer.promisc :=true;    
raw_sniffer.str_ip :=ip;
raw_sniffer.OnPacket :=obj.OnPacket ;
raw_sniffer.OnError :=obj.OnError ;
try
  raw_sniffer.opensocket_;
except
on e:exception do begin writeln(e.message);exit;end;
end;

if cap=true then open_cap ;

writeln('sniffing on '+ip);
while (GetMessage(Msg,0,0,0))   do
begin
{these will get the messages to the window they should go to}
  if error=true then break;
  TranslateMessage(Msg);
  DispatchMessage(Msg);
  if HiWord(GetAsyncKeyState(VK_ESCAPE)) <> 0 then break;
end;

if cap=true then close_cap ;
raw_sniffer.closesocket_ ;

try
  if (paramcount>=5) and (paramstr(5)='1') then
     begin
     writeln('removing inbound firewall exception');
     DeleteFromWinFirewallNT6('snif');
     end;
except
on e:exception do writeln('DeleteFromWinFirewall3 failed:'+e.message);
end;
end.
