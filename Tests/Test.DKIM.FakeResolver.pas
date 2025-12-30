unit Test.DKIM.FakeResolver;

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  DNS.SPF.Types;

type
  TFakeDkimDnsResolver = class(TInterfacedObject, ISpfDnsResolver)
  private
    FTxt: TDictionary<string, TArray<string>>;
  public
    constructor Create;
    destructor Destroy; override;

    procedure AddTxt(const Name: string; const Values: TArray<string>);

    function QueryTXT(const Name: string; out Txts: TArray<string>): TDnsStatus;

    // Unused resolver methods
    function QueryA(const Name: string; out Addrs: TArray<string>): TDnsStatus;
    function QueryAAAA(const Name: string; out Addrs: TArray<string>): TDnsStatus;
    function QueryMX(const Name: string; out Hosts: TArray<string>): TDnsStatus;
    function QueryNS(const Name: string; out Hosts: TArray<string>): TDnsStatus;
  end;

implementation

constructor TFakeDkimDnsResolver.Create;
begin
  inherited;
  FTxt := TDictionary<string, TArray<string>>.Create;
end;

destructor TFakeDkimDnsResolver.Destroy;
begin
  FTxt.Free;
  inherited;
end;

procedure TFakeDkimDnsResolver.AddTxt(
  const Name: string;
  const Values: TArray<string>
);
begin
  FTxt.AddOrSetValue(LowerCase(Name), Values);
end;

function TFakeDkimDnsResolver.QueryTXT(
  const Name: string;
  out Txts: TArray<string>
): TDnsStatus;
begin
  if FTxt.TryGetValue(LowerCase(Name), Txts) then
    Result := dnsOk
  else
  begin
    Txts := nil;
    Result := dnsNoData;
  end;
end;

// Stub everything else
function TFakeDkimDnsResolver.QueryA(const Name: string; out Addrs: TArray<string>): TDnsStatus;
begin
  Addrs := nil;
  Result := dnsNoData;
end;

function TFakeDkimDnsResolver.QueryAAAA(const Name: string; out Addrs: TArray<string>): TDnsStatus;
begin
  Addrs := nil;
  Result := dnsNoData;
end;

function TFakeDkimDnsResolver.QueryMX(const Name: string; out Hosts: TArray<string>): TDnsStatus;
begin
  Hosts := nil;
  Result := dnsNoData;
end;

function TFakeDkimDnsResolver.QueryNS(const Name: string; out Hosts: TArray<string>): TDnsStatus;
begin
  Hosts := nil;
  Result := dnsNoData;
end;

end.
