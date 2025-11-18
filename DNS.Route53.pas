unit DNS.Route53;

interface

uses
  System.SysUtils,
  System.Classes,
  System.Generics.Collections,
  System.DateUtils,
  System.NetEncoding,
  System.Hash,
  System.JSON,
  System.Net.URLClient,
  REST.Types,
  REST.Client,
  DNS.Base;

type
  TRoute53DNSProvider = class(TBaseDNSProvider)
  private
    FAwsAccessKey: string;
    FAwsSecretKey: string;
    FRegion: string;

    function NowUTC: TDateTime;
    function ISO8601DateTime(const ADT: TDateTime): string;
    function ISO8601Date(const ADT: TDateTime): string;
    function BytesToHexString(const Bytes: TBytes): string;

    function HmacSHA256(const AKey: TBytes; const AData: string): TBytes;
    function CalculateSignature(const ASecretKey, ADate, ARegion, AService, AStringToSign: string): string;
    function BuildCanonicalRequest(const AMethod: string; const ACanonicalUri, ACanonicalQuery, ACanonicalHeaders, ASignedHeaders, APayloadHash: string): string;
    function BuildStringToSign(const ARequestDateTime, ACredentialScope, AHashedCanonicalRequest: string): string;

    function MethodToString(AMethod: TRESTRequestMethod): string;

    procedure SignRequest(const AMethod: TRESTRequestMethod; const AResource: string);
  protected
    procedure SetAuthHeaders; override;

    function GetRecordTypeString(AType: TDNSRecordType): string; override;
    function ParseRecordType(const ATypeStr: string): TDNSRecordType; override;

    function ParseRecord(AJson: TJSONObject): TDNSRecord; override;
    function RecordToJSON(ARecord: TDNSRecord; const AAction: string = 'UPSERT'): TJSONObject;
    function ParseZone(AJson: TJSONObject): TDNSZone; override;
  public
    constructor Create(const AAwsAccessKey, AAwsSecretKey: string; const ARegion: string = 'us-east-1'); reintroduce;

    function ListZones: TObjectList<TDNSZone>; override;
    function GetZone(const ADomain: string): TDNSZone; override;
    function CreateZone(const ADomain: string): TDNSZone; override;
    function DeleteZone(const ADomain: string): Boolean; override;

    function ListRecords(const ADomain: string; ARecordType: TDNSRecordType = drtA): TObjectList<TDNSRecord>; override;
    function GetRecord(const ADomain, ARecordId: string): TDNSRecord; override;
    function CreateRecord(const ADomain: string; ARecord: TDNSRecord): TDNSRecord; override;
    function UpdateRecord(const ADomain: string; ARecord: TDNSRecord): Boolean; override;
    function DeleteRecord(const ADomain, ARecordId: string): Boolean; override;
  end;

implementation

{ Helper Functions }

function TRoute53DNSProvider.BytesToHexString(const Bytes: TBytes): string;
const
  HexChars: array[0..15] of Char = ('0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F');
var
  I: Integer;
begin
  SetLength(Result, Length(Bytes) * 2);
  for I := 0 to Length(Bytes) - 1 do
  begin
    Result[I * 2 + 1] := HexChars[Bytes[I] shr 4];
    Result[I * 2 + 2] := HexChars[Bytes[I] and $0F];
  end;
  Result := LowerCase(Result);
end;

function TRoute53DNSProvider.NowUTC: TDateTime;
begin
  Result := TDateTime.NowUTC;
end;

function TRoute53DNSProvider.ISO8601DateTime(const ADT: TDateTime): string;
begin
  Result := FormatDateTime('yyyymmdd"T"hhnnss"Z"', ADT);
end;

function TRoute53DNSProvider.ISO8601Date(const ADT: TDateTime): string;
begin
  Result := FormatDateTime('yyyymmdd', ADT);
end;

function TRoute53DNSProvider.MethodToString(AMethod: TRESTRequestMethod): string;
begin
  case AMethod of
    rmGET:    Result := 'GET';
    rmPOST:   Result := 'POST';
    rmPUT:    Result := 'PUT';
    rmDELETE: Result := 'DELETE';
    rmPATCH:  Result := 'PATCH';
  else
    Result := 'GET';
  end;
end;

function TRoute53DNSProvider.HmacSHA256(const AKey: TBytes; const AData: string): TBytes;
var
  Hasher: THashSHA2;
begin
  Hasher := THashSHA2.Create(SHA256);
  Hasher.Update(AKey);
  Hasher.Update(TEncoding.UTF8.GetBytes(AData));
  Result := Hasher.HashAsBytes;
end;

function TRoute53DNSProvider.CalculateSignature(const ASecretKey, ADate, ARegion, AService, AStringToSign: string): string;
var
  kDate, kRegion, kService, kSigning, Sig: TBytes;
begin
  kDate := HmacSHA256(TEncoding.UTF8.GetBytes('AWS4' + ASecretKey), ADate);
  kRegion := HmacSHA256(kDate, ARegion);
  kService := HmacSHA256(kRegion, AService);
  kSigning := HmacSHA256(kService, 'aws4_request');
  Sig := HmacSHA256(kSigning, AStringToSign);
  Result := BytesToHexString(Sig);
end;

function TRoute53DNSProvider.BuildCanonicalRequest(const AMethod: string; const ACanonicalUri, ACanonicalQuery, ACanonicalHeaders, ASignedHeaders, APayloadHash: string): string;
begin
  Result := AMethod + #10 +
            ACanonicalUri + #10 +
            ACanonicalQuery + #10 +
            ACanonicalHeaders + #10 +
            ASignedHeaders + #10 +
            APayloadHash;
end;

function TRoute53DNSProvider.BuildStringToSign(const ARequestDateTime, ACredentialScope, AHashedCanonicalRequest: string): string;
begin
  Result := 'AWS4-HMAC-SHA256' + #10 +
            ARequestDateTime + #10 +
            ACredentialScope + #10 +
            AHashedCanonicalRequest;
end;

procedure TRoute53DNSProvider.SignRequest(const AMethod: TRESTRequestMethod; const AResource: string);
var
  AmzDate, DateStamp, PayloadHash, Host, UriPath, QueryString: string;
  CanonicalHeaders, SignedHeaders, CredentialScope: string;
  CanonicalRequest, HashedCanonicalRequest, StringToSign, Signature: string;
  AuthHeader: string;
  URI: TURI;
  NowDT: TDateTime;
  Payload: string;
begin
  NowDT := NowUTC;
  AmzDate := ISO8601DateTime(NowDT);
  DateStamp := ISO8601Date(NowDT);

  Payload := TCustomRESTRequest(FRestRequest).GetFullRequestBody;

  if Payload = '' then
    PayloadHash := 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  else
    PayloadHash := THashSHA2.GetHashString(Payload, SHA256);

  URI := TURI.Create('https://route53.amazonaws.com' + AResource);
  Host := URI.Host;
  UriPath := TNetEncoding.URL.EncodePath(URI.Path);
  QueryString := TNetEncoding.URL.EncodeQuery(URI.Query);

  CanonicalHeaders := 'host:' + Host + #10 +
                      'x-amz-content-sha256:' + PayloadHash + #10 +
                      'x-amz-date:' + AmzDate + #10;

  SignedHeaders := 'host;x-amz-content-sha256;x-amz-date';

  CredentialScope := DateStamp + '/' + FRegion + '/route53/aws4_request';

  CanonicalRequest := BuildCanonicalRequest(
    MethodToString(AMethod),
    UriPath, QueryString, CanonicalHeaders, SignedHeaders, PayloadHash);

  HashedCanonicalRequest := THashSHA2.GetHashString(CanonicalRequest, SHA256);

  StringToSign := BuildStringToSign(AmzDate, CredentialScope, HashedCanonicalRequest);

  Signature := CalculateSignature(FAwsSecretKey, DateStamp, FRegion, 'route53', StringToSign);

  AuthHeader := 'AWS4-HMAC-SHA256 Credential=' + FAwsAccessKey + '/' + CredentialScope +
                ', SignedHeaders=' + SignedHeaders +
                ', Signature=' + Signature;

  FRestRequest.Params.Clear;
  FRestRequest.AddParameter('Authorization', AuthHeader, pkHTTPHEADER, [poDoNotEncode]);
  FRestRequest.AddParameter('x-amz-date', AmzDate, pkHTTPHEADER, [poDoNotEncode]);
  FRestRequest.AddParameter('x-amz-content-sha256', PayloadHash, pkHTTPHEADER, [poDoNotEncode]);
end;

procedure TRoute53DNSProvider.SetAuthHeaders;
begin
  SignRequest(FRestRequest.Method, FRestRequest.Resource);
end;

function TRoute53DNSProvider.GetRecordTypeString(AType: TDNSRecordType): string;
begin
  Result := inherited GetRecordTypeString(AType);
end;

function TRoute53DNSProvider.ParseRecordType(const ATypeStr: string): TDNSRecordType;
begin
  Result := inherited ParseRecordType(ATypeStr);
end;

function TRoute53DNSProvider.ParseZone(AJson: TJSONObject): TDNSZone;
var
  LId, LName: string;
begin
  Result := TDNSZone.Create;
  try
    if AJson.TryGetValue<string>('Id', LId) then
      Result.Id := Copy(LId, Pos('/hostedzone/', LId) + 12, MaxInt);

    if AJson.TryGetValue<string>('Name', LName) then
    begin
      Result.Domain := LName;
      if Result.Domain.EndsWith('.') then
      begin
        Result.Domain := Copy(Result.Domain, 1, Length(Result.Domain) - 2);
      end;
    end;
  except
    FreeAndNil(Result);
    raise;
  end;
end;

function TRoute53DNSProvider.ParseRecord(AJson: TJSONObject): TDNSRecord;
var
  LName, LType, LValue: string;
  LTTL: Int64;
  LRecords: TJSONArray;
begin
  Result := TDNSRecord.Create;
  try
    if AJson.TryGetValue<string>('Name', LName) then
    begin
      Result.Name := LName;
      if Result.Name.EndsWith('.') then
        Result.Name := Copy(Result.Name, 1, Length(Result.Name) - 2);
    end;

    if AJson.TryGetValue<string>('Type', LType) then
      Result.RecordType := ParseRecordType(LType);

    if not AJson.TryGetValue<Int64>('TTL', LTTL) then
      LTTL := 300;
    Result.TTL := LTTL;

    if AJson.TryGetValue<TJSONArray>('ResourceRecords', LRecords) and (LRecords.Count > 0) then
      Result.Value := LRecords.Items[0].GetValue<string>('Value');
  except
    FreeAndNil(Result);
    raise;
  end;
end;

function TRoute53DNSProvider.RecordToJSON(ARecord: TDNSRecord; const AAction: string): TJSONObject;
var
  Changes: TJSONArray;
  Change, RRSet, RR: TJSONObject;
begin
  Changes := TJSONArray.Create;

  Change := TJSONObject.Create;
  Change.AddPair('Action', AAction);

  RRSet := TJSONObject.Create;
  RRSet.AddPair('Name', ARecord.Name + '.');
  RRSet.AddPair('Type', GetRecordTypeString(ARecord.RecordType));
  RRSet.AddPair('TTL', TJSONNumber.Create(ARecord.TTL));

  RR := TJSONObject.Create;
  RR.AddPair('Value', ARecord.Value);
  RRSet.AddPair('ResourceRecords', TJSONArray.Create.Add(RR));

  Change.AddPair('ResourceRecordSet', RRSet);
  Changes.Add(Change);

  Result := TJSONObject.Create;
  Result.AddPair('Changes', Changes);
end;

constructor TRoute53DNSProvider.Create(const AAwsAccessKey, AAwsSecretKey: string; const ARegion: string);
begin
  inherited Create('', '');
  FAwsAccessKey := AAwsAccessKey;
  FAwsSecretKey := AAwsSecretKey;
  FRegion := ARegion;
  FRestClient.BaseURL := 'https://route53.amazonaws.com';
end;

function TRoute53DNSProvider.ListZones: TObjectList<TDNSZone>;
var
  Resp: TJSONValue;
  Zones: TJSONArray;
  i: Integer;
begin
  Result := TObjectList<TDNSZone>.Create(True);
  Resp := ExecuteRequest(rmGET, '/2013-04-01/hostedzones');
  try
    if (Resp is TJSONObject) then
    begin
      Zones := TJSONObject(Resp).GetValue<TJSONArray>('HostedZones');
      if Assigned(Zones) then
        for i := 0 to Zones.Count - 1 do
          Result.Add(ParseZone(Zones.Items[i] as TJSONObject));
    end;
  finally
    FreeAndNil(Resp);
  end;
end;

function TRoute53DNSProvider.GetZone(const ADomain: string): TDNSZone;
var
  Zones: TObjectList<TDNSZone>;
  Z: TDNSZone;
begin
  Zones := ListZones;
  try
    for Z in Zones do
      if SameText(Z.Domain, ADomain) or SameText(Z.Domain, ADomain + '.') then
      begin
        Result := Z.Clone;
        Exit;
      end;
  finally
    FreeAndNil(Zones);
  end;
  raise EDNSZoneNotFound.Create('Zone not found: ' + ADomain);
end;

function TRoute53DNSProvider.CreateZone(const ADomain: string): TDNSZone;
var
  Payload, Resp: TJSONObject;
begin
  Payload := TJSONObject.Create;
  try
    Payload.AddPair('Name', ADomain + '.');
    Payload.AddPair('CallerReference', TGuid.NewGuid.ToString);

    Resp := ExecuteRequest(rmPOST, '/2013-04-01/hostedzone', Payload) as TJSONObject;
    try
      Result := ParseZone(Resp.GetValue<TJSONObject>('HostedZone'));
    finally
      FreeAndNil(Resp);
    end;
  finally
    FreeAndNil(Payload);
  end;
end;

function TRoute53DNSProvider.DeleteZone(const ADomain: string): Boolean;
var
  Zone: TDNSZone;
begin
  Zone := GetZone(ADomain);
  try
    ExecuteRequest(rmDELETE, '/2013-04-01/hostedzone/' + Zone.Id);
    Result := True;
  finally
    FreeAndNil(Zone);
  end;
end;

function TRoute53DNSProvider.ListRecords(const ADomain: string; ARecordType: TDNSRecordType): TObjectList<TDNSRecord>;
var
  Zone: TDNSZone;
  Resp: TJSONObject;
  RRsets: TJSONArray;
  i: Integer;
  Rec: TDNSRecord;
begin
  Result := TObjectList<TDNSRecord>.Create(True);
  Zone := GetZone(ADomain);
  try
    Resp := ExecuteRequest(rmGET, '/2013-04-01/hostedzone/' + Zone.Id + '/rrset') as TJSONObject;
    try
      RRsets := Resp.GetValue<TJSONArray>('ResourceRecordSets');
      if Assigned(RRsets) then
        for i := 0 to RRsets.Count - 1 do
        begin
          Rec := ParseRecord(RRsets.Items[i] as TJSONObject);
          if (ARecordType = drtA) or (Rec.RecordType = ARecordType) then
            Result.Add(Rec)
          else
            FreeAndNil(Rec);
        end;
    finally
      FreeAndNil(Resp);
    end;
  finally
    FreeAndNil(Zone);
  end;
end;

function TRoute53DNSProvider.CreateRecord(const ADomain: string; ARecord: TDNSRecord): TDNSRecord;
var
  Zone: TDNSZone;
  Payload: TJSONObject;
begin
  if not ValidateRecord(ARecord) then
    raise EDNSException.Create('Invalid record');

  Zone := GetZone(ADomain);
  try
    Payload := RecordToJSON(ARecord, 'UPSERT');
    try
      ExecuteRequest(rmPOST, '/2013-04-01/hostedzone/' + Zone.Id + '/rrset', Payload);
      Result := ARecord.Clone;
    finally
      FreeAndNil(Payload);
    end;
  finally
    FreeAndNil(Zone);
  end;
end;

function TRoute53DNSProvider.UpdateRecord(const ADomain: string; ARecord: TDNSRecord): Boolean;
begin
  CreateRecord(ADomain, ARecord);
  Result := True;
end;

function TRoute53DNSProvider.DeleteRecord(const ADomain, ARecordId: string): Boolean;
var
  Rec: TDNSRecord;
  Payload: TJSONObject;
  Zone: TDNSZone;
begin
  Rec := GetRecord(ADomain, ARecordId);
  try
    Payload := RecordToJSON(Rec, 'DELETE');
    Zone := GetZone(ADomain);
    try
      ExecuteRequest(rmPOST, '/2013-04-01/hostedzone/' + Zone.Id + '/rrset', Payload);
      Result := True;
    finally
      FreeAndNil(Zone);
    end;
  finally
    FreeAndNil(Payload);
    FreeAndNil(Rec);
  end;
end;

function TRoute53DNSProvider.GetRecord(const ADomain, ARecordId: string): TDNSRecord;
var
  AllRecs: TObjectList<TDNSRecord>;
  R: TDNSRecord;
begin
  AllRecs := ListRecords(ADomain);
  try
    for R in AllRecs do
      if SameText(R.Name, ARecordId) then
      begin
        Result := R.Clone;
        Exit;
      end;
  finally
    FreeAndNil(AllRecs);
  end;
  raise EDNSRecordNotFound.Create('Record not found: ' + ARecordId);
end;

end.
