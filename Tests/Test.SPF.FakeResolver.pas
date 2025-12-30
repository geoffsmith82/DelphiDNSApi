unit Test.SPF.FakeResolver;

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  DNS.SPF.Types;

type
  TFakeSpfDnsResolver = class(TInterfacedObject, ISpfDnsResolver)
  private
    FTxt: TDictionary<string, TArray<string>>;
    FA: TDictionary<string, TArray<string>>;
    FAAAA: TDictionary<string, TArray<string>>;
    FMX: TDictionary<string, TArray<string>>;
  public
    constructor Create;
    destructor Destroy; override;

    procedure AddTXT(const Domain: string; const Values: array of string);
    procedure AddA(const Domain: string; const Addrs: array of string);
    procedure AddAAAA(const Domain: string; const Addrs: array of string);
    procedure AddMX(const Domain: string; const Hosts: array of string);

    function QueryTXT(const Name: string; out Txt: TArray<string>): TDnsStatus;
    function QueryA(const Name: string; out Addrs: TArray<string>): TDnsStatus;
    function QueryAAAA(const Name: string; out Addrs: TArray<string>): TDnsStatus;
    function QueryMX(const Name: string; out Hosts: TArray<string>): TDnsStatus;
  end;

implementation

function OpenArrayToArray(const A: array of string): TArray<string>;
var
  I: Integer;
begin
  SetLength(Result, Length(A));
  for I := 0 to High(A) do
    Result[I] := A[I];
end;



constructor TFakeSpfDnsResolver.Create;
begin
  inherited Create;
  FTxt := TDictionary<string, TArray<string>>.Create;
  FA := TDictionary<string, TArray<string>>.Create;
  FAAAA := TDictionary<string, TArray<string>>.Create;
  FMX := TDictionary<string, TArray<string>>.Create;
end;

destructor TFakeSpfDnsResolver.Destroy;
begin
  FreeAndNil(FTxt);
  FreeAndNil(FA);
  FreeAndNil(FAAAA);
  FreeAndNil(FMX);
  inherited Destroy;
end;

procedure TFakeSpfDnsResolver.AddTXT(const Domain: string; const Values: array of string);
begin
  FTxt.AddOrSetValue(LowerCase(Domain), OpenArrayToArray(Values));
end;

procedure TFakeSpfDnsResolver.AddA(const Domain: string; const Addrs: array of string);
begin
  FA.AddOrSetValue(LowerCase(Domain), OpenArrayToArray(Addrs));
end;

procedure TFakeSpfDnsResolver.AddAAAA(const Domain: string; const Addrs: array of string);
begin
  FAAAA.AddOrSetValue(LowerCase(Domain), OpenArrayToArray(Addrs));

end;

procedure TFakeSpfDnsResolver.AddMX(const Domain: string; const Hosts: array of string);
begin
  FMX.AddOrSetValue(LowerCase(Domain), OpenArrayToArray(Hosts));

end;

function TFakeSpfDnsResolver.QueryTXT(const Name: string; out Txt: TArray<string>): TDnsStatus;
begin
  if FTxt.TryGetValue(LowerCase(Name), Txt) then
    Exit(dnsOk);

  Txt := nil;
  Result := dnsNoData;
end;

function TFakeSpfDnsResolver.QueryA(const Name: string; out Addrs: TArray<string>): TDnsStatus;
begin
  if FA.TryGetValue(LowerCase(Name), Addrs) then
    Exit(dnsOk);

  Addrs := nil;
  Result := dnsNoData;
end;

function TFakeSpfDnsResolver.QueryAAAA(const Name: string; out Addrs: TArray<string>): TDnsStatus;
begin
  if FAAAA.TryGetValue(LowerCase(Name), Addrs) then
    Exit(dnsOk);

  Addrs := nil;
  Result := dnsNoData;
end;

function TFakeSpfDnsResolver.QueryMX(const Name: string; out Hosts: TArray<string>): TDnsStatus;
begin
  if FMX.TryGetValue(LowerCase(Name), Hosts) then
    Exit(dnsOk);

  Hosts := nil;
  Result := dnsNoData;
end;

end.

