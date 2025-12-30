unit DNS.SPF.DnsCache;

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  DNS.SPF.Types;

type
  TSpfCachingResolver = class(TInterfacedObject, ISpfDnsResolver)
  private
    FInner: ISpfDnsResolver;

    FTxtCache: TDictionary<string, TArray<string>>;
    FACache: TDictionary<string, TArray<string>>;
    FAAAACache: TDictionary<string, TArray<string>>;
    FMXCache: TDictionary<string, TArray<string>>;

    FTxtStatus: TDictionary<string, TDnsStatus>;
    FAStatus: TDictionary<string, TDnsStatus>;
    FAAAAStatus: TDictionary<string, TDnsStatus>;
    FMXStatus: TDictionary<string, TDnsStatus>;

    function KeyOf(const Name: string): string;
  public
    constructor Create(const Inner: ISpfDnsResolver);
    destructor Destroy; override;

    function QueryTXT(const Name: string; out Txt: TArray<string>): TDnsStatus;
    function QueryA(const Name: string; out Addrs: TArray<string>): TDnsStatus;
    function QueryAAAA(const Name: string; out Addrs: TArray<string>): TDnsStatus;
    function QueryMX(const Name: string; out Hosts: TArray<string>): TDnsStatus;
  end;

implementation

function TSpfCachingResolver.KeyOf(const Name: string): string;
begin
  Result := LowerCase(Trim(Name));
end;

constructor TSpfCachingResolver.Create(const Inner: ISpfDnsResolver);
begin
  inherited Create;
  FInner := Inner;

  FTxtCache := TDictionary<string, TArray<string>>.Create;
  FACache := TDictionary<string, TArray<string>>.Create;
  FAAAACache := TDictionary<string, TArray<string>>.Create;
  FMXCache := TDictionary<string, TArray<string>>.Create;

  FTxtStatus := TDictionary<string, TDnsStatus>.Create;
  FAStatus := TDictionary<string, TDnsStatus>.Create;
  FAAAAStatus := TDictionary<string, TDnsStatus>.Create;
  FMXStatus := TDictionary<string, TDnsStatus>.Create;
end;

destructor TSpfCachingResolver.Destroy;
begin
  FreeAndNil(FTxtCache);
  FreeAndNil(FACache);
  FreeAndNil(FAAAACache);
  FreeAndNil(FMXCache);

  FreeAndNil(FTxtStatus);
  FreeAndNil(FAStatus);
  FreeAndNil(FAAAAStatus);
  FreeAndNil(FMXStatus);

  inherited Destroy;
end;

function TSpfCachingResolver.QueryTXT(const Name: string; out Txt: TArray<string>): TDnsStatus;
var
  K: string;
begin
  K := KeyOf(Name);

  if FTxtStatus.TryGetValue(K, Result) then
  begin
    FTxtCache.TryGetValue(K, Txt);
    Exit;
  end;

  Result := FInner.QueryTXT(Name, Txt);
  FTxtStatus.AddOrSetValue(K, Result);
  FTxtCache.AddOrSetValue(K, Txt);
end;

function TSpfCachingResolver.QueryA(const Name: string; out Addrs: TArray<string>): TDnsStatus;
var
  K: string;
begin
  K := KeyOf(Name);

  if FAStatus.TryGetValue(K, Result) then
  begin
    FACache.TryGetValue(K, Addrs);
    Exit;
  end;

  Result := FInner.QueryA(Name, Addrs);
  FAStatus.AddOrSetValue(K, Result);
  FACache.AddOrSetValue(K, Addrs);
end;

function TSpfCachingResolver.QueryAAAA(const Name: string; out Addrs: TArray<string>): TDnsStatus;
var
  K: string;
begin
  K := KeyOf(Name);

  if FAAAAStatus.TryGetValue(K, Result) then
  begin
    FAAAACache.TryGetValue(K, Addrs);
    Exit;
  end;

  Result := FInner.QueryAAAA(Name, Addrs);
  FAAAAStatus.AddOrSetValue(K, Result);
  FAAAACache.AddOrSetValue(K, Addrs);
end;

function TSpfCachingResolver.QueryMX(const Name: string; out Hosts: TArray<string>): TDnsStatus;
var
  K: string;
begin
  K := KeyOf(Name);

  if FMXStatus.TryGetValue(K, Result) then
  begin
    FMXCache.TryGetValue(K, Hosts);
    Exit;
  end;

  Result := FInner.QueryMX(Name, Hosts);
  FMXStatus.AddOrSetValue(K, Result);
  FMXCache.AddOrSetValue(K, Hosts);
end;

end.

