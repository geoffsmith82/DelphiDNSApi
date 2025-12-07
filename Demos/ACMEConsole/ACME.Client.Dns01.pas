unit ACME.Client.Dns01;

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  ACME.Client.Types,
  ACME.TaurusCrypto,
  DNS.Base;

type
  // DNS-01 solver using your TBaseDNSProvider directly
  TAcmeDns01Solver = class(TInterfacedObject, IAcmeChallengeSolver)
  private
    FProvider: TBaseDNSProvider;
    FCreatedRecords: TDictionary<string,string>; // domain → recordId
    function FindBestZone(const Domain: string; out ZoneName: string): Boolean;
    function BuildRecordName(const Domain, ZoneName: string): string;
  public
    constructor Create(AProvider: TBaseDNSProvider);
    destructor Destroy; override;

    function CanSolve(const ChallengeType: TChallengeType): Boolean;
    procedure Solve(const Domain: string; const Challenge: TAcmeChallenge; const TxtValue: string);
    procedure Cleanup(const Domain: string; const Challenge: TAcmeChallenge);
  end;

implementation

{ === TAcmeDns01Solver =================================================== }

constructor TAcmeDns01Solver.Create(AProvider: TBaseDNSProvider);
begin
  inherited Create;
  FProvider := AProvider;
  FCreatedRecords := TDictionary<string,string>.Create;
end;

destructor TAcmeDns01Solver.Destroy;
begin
  FreeAndNil(FCreatedRecords);
  inherited;
end;

function TAcmeDns01Solver.CanSolve(const ChallengeType: TChallengeType): Boolean;
begin
  Result := ChallengeType = TChallengeType.ctDns01;
end;

function TAcmeDns01Solver.FindBestZone(const Domain: string; out ZoneName: string): Boolean;
var
  Zones: TObjectList<TDNSZone>;
  Z: TDNSZone;
  BestLen: Integer;
begin
  Result := False;
  ZoneName := '';
  BestLen := 0;

  Zones := FProvider.ListZones;
  try
    for Z in Zones do
    begin
      if SameText(Domain, Z.Domain) or
         SameText(Copy(Domain, Length(Domain) - Length(Z.Domain) + 1, MaxInt), Z.Domain) then
      begin
        if Length(Z.Domain) > BestLen then
        begin
          BestLen := Length(Z.Domain);
          ZoneName := Z.Domain;
          Result := True;
        end;
      end;
    end;
  finally
    FreeAndNil(Zones);
  end;
end;

function TAcmeDns01Solver.BuildRecordName(const Domain, ZoneName: string): string;
var
  SubPart: string;
begin
  if SameText(Domain, ZoneName) then
    SubPart := ''
  else if SameText(Copy(Domain, Length(Domain) - Length(ZoneName) + 1, MaxInt), ZoneName) then
    SubPart := Copy(Domain, 1, Length(Domain) - Length(ZoneName) - 1)
  else
    SubPart := Domain; // fallback: fqdn

  if SubPart = '' then
    Result := '_acme-challenge'
  else
    Result := '_acme-challenge.' + SubPart;
end;



procedure TAcmeDns01Solver.Solve(const Domain: string; const Challenge: TAcmeChallenge; const TxtValue: string);
var
  ZoneName: string;
  Rec, Created: TDNSRecord;
begin
  if not FindBestZone(Domain, ZoneName) then
    raise EDNSZoneNotFound.CreateFmt('No DNS zone found for %s', [Domain]);

  Rec := TDNSRecord.Create;
  try
    Rec.Name := BuildRecordName(Domain, ZoneName);   // "_acme-challenge.<subdomain>"
    Rec.RecordType := drtTXT;
    Rec.Value := TxtValue;                           // <-- ACME client already computed
    Rec.TTL := 60;

    Created := FProvider.CreateRecord(ZoneName, Rec);
    try
      if Created = nil then
        raise EDNSAPIException.Create('CreateRecord returned nil');

      FCreatedRecords.AddOrSetValue(Domain, Created.Id);
    finally
      FreeAndNil(Created);
    end;
  finally
    FreeAndNil(Rec);
  end;
end;

procedure TAcmeDns01Solver.Cleanup(const Domain: string; const Challenge: TAcmeChallenge);
var
  ZoneName, RecordId: string;
begin
  if not FindBestZone(Domain, ZoneName) then
    Exit;
  if FCreatedRecords.TryGetValue(Domain, RecordId) then
  begin
    try
      FProvider.DeleteRecord(ZoneName, RecordId);
    except
      // ignore cleanup errors
    end;
  end;
end;


end.
