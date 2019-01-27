unit firewall;

{$mode delphi}

interface

uses
  Classes, SysUtils,comobj,NetFwTypeLib_TLB;


procedure DeleteFromWinFirewallNT6(const RuleName: wideString);
procedure AddFirewallExceptionNT6(const Caption, AppPath: wideString;
    const dir:NET_FW_RULE_DIRECTION_=NET_FW_RULE_DIR_IN;
    const action:NET_FW_ACTION_=NET_FW_ACTION_ALLOW;
    const protocol:NET_FW_IP_PROTOCOL_=NET_FW_IP_PROTOCOL_ANY;
    const ports_or_IcmpTypesAndCodes:widestring='');

const
  NET_FW_IP_PROTOCOL_ICMPv4 = 1;
  NET_FW_IP_PROTOCOL_ICMPv6 = 58;

implementation

//we could add ourselve outbound to the firewall...since we have to run as local admin
//and remove ourselve on exit...
procedure AddFirewallExceptionNT6(const Caption, AppPath: wideString;
    const dir:NET_FW_RULE_DIRECTION_=NET_FW_RULE_DIR_IN;
    const action:NET_FW_ACTION_=NET_FW_ACTION_ALLOW;
    const protocol:NET_FW_IP_PROTOCOL_=NET_FW_IP_PROTOCOL_ANY;
    const ports_or_IcmpTypesAndCodes:widestring='');
var
  Profile: Integer;
  Policy2: OleVariant;
  RObject: OleVariant;
  NewRule: OleVariant;
begin
  //Profile := NET_FW_PROFILE2_PRIVATE OR NET_FW_PROFILE2_PUBLIC or NET_FW_PROFILE2_DOMAIN;
  if caption='' then exit;
  Profile :=NET_FW_PROFILE2_ALL;
  Policy2 := CreateOleObject('HNetCfg.FwPolicy2');
  RObject := Policy2.Rules;
  NewRule := CreateOleObject('HNetCfg.FWRule');
  NewRule.Name        := Caption;
  NewRule.Description := Caption;
  if apppath<>'' then NewRule.ApplicationName := AppPath;
  NewRule.direction:=dir;
  NewRule.Protocol := protocol;
  if (protocol=NET_FW_IP_PROTOCOL_TCP) or (protocol=NET_FW_IP_PROTOCOL_UDP) then
  begin
  if (ports_or_IcmpTypesAndCodes<>'') and (dir=NET_FW_RULE_DIR_IN) then
    begin
    NewRule.localports:=ports_or_IcmpTypesAndCodes;
    end;
  if (ports_or_IcmpTypesAndCodes<>'') and (dir=NET_FW_RULE_DIR_OUT) then
    begin
    NewRule.RemotePorts:=ports_or_IcmpTypesAndCodes;
    end;
  end;
  if protocol=NET_FW_IP_PROTOCOL_ICMPv4 then NewRule.IcmpTypesAndCodes:=ports_or_IcmpTypesAndCodes;
  NewRule.Enabled := True;
  NewRule.Grouping := '';
  NewRule.Profiles := Profile;
  NewRule.Action := action;
  RObject.Add(NewRule);
end;

{
//appname pour nt6 - filename pour nt5
CoInitialize(nil);
DeleteFromWinFirewall3(app);
CoUninitialize;
}

procedure DeleteFromWinFirewallNT6(const RuleName: wideString);
var
  Profile: Integer;
  Policy2: OleVariant;
  RObject: OleVariant;
  policy3: INetFwPolicy2;
begin
  //Profile := NET_FW_PROFILE2_PRIVATE OR NET_FW_PROFILE2_PUBLIC or NET_FW_PROFILE2_DOMAIN;
  Profile :=NET_FW_PROFILE2_ALL;
  //policy3 := INetFwPolicy2(CreateOleObject( 'HNetCfg.FwPolicy2' ));
  //policy3.Rules.Remove(rulename);
  Policy2 := CreateOleObject('HNetCfg.FwPolicy2');
  RObject := Policy2.Rules;
  RObject.Remove(RuleName);
end;

end.

