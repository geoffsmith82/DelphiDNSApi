unit Test.SPF.RealDns.Base;

interface

uses
  DUnitX.TestFramework,
  DNS.SPF.Engine,
  DNS.SPF.DnsWin32,
  DNS.SPF.Types;

type
  TRealDnsTestBase = class
  protected
    function CreateEngine: TSpfEngine;
    function CreateResolver: ISpfDnsResolver;
    function HasInternet: Boolean;
  end;

implementation

uses
  Winapi.WinSock2;

function TRealDnsTestBase.CreateEngine: TSpfEngine;
begin
  Result := TSpfEngine.Create;
end;

function TRealDnsTestBase.CreateResolver: ISpfDnsResolver;
begin
  Result := TSpfWinDnsResolver.Create;
end;

function TRealDnsTestBase.HasInternet: Boolean;
var
  WSA: TWSAData;
begin
  // Very cheap sanity check
  Result := WSAStartup($0202, WSA) = 0;
end;

end.

