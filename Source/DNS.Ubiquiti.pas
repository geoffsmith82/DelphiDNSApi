unit DNS.Ubiquiti;

interface

uses
  System.SysUtils,
  System.Classes,
  System.JSON,
  System.Generics.Collections,
  System.Net.HttpClient,
  REST.Types,
  REST.Client,
  DNS.Base;

type
  TUbiquitiDNSProvider = class(TBaseDNSProvider)
  private
    FSite: string;
    FBaseURL: string;
    FUsername: string;
    FPassword: string;
    F2FAToken: string;
    FSessionCookie: string;
    FCSRFToken: string;

    FDnsListResource: string;
    FDnsItemResource: string;

    function DoLogin: Boolean;
    procedure ExtractSessionData(const Response: TRESTResponse);

    const
      UNI_SINGLE_ZONE_ID   = 'default';
      UNI_SINGLE_ZONE_NAME = 'default';
  protected
    procedure SetAuthHeaders; override;

    function ParseRecord(AJson: TJSONObject): TDNSRecord; override;
    function RecordToJSON(ARecord: TDNSRecord): TJSONObject; override;
    function ParseZone(AJson: TJSONObject): TDNSZone; override;
  public
    constructor Create(const AURL, AUsername, APassword, A2FAToken: string);

    function ListZones: TObjectList<TDNSZone>; override;
    function GetZone(const ADomain: string): TDNSZone; override;
    function CreateZone(const ADomain: string): TDNSZone; override;
    function DeleteZone(const ADomain: string): Boolean; override;

    function ListRecords(const ADomain: string; ARecordType: TDNSRecordType = drtA): TObjectList<TDNSRecord>; override;
    function GetRecord(const ADomain, ARecordId: string): TDNSRecord; override;
    function CreateRecord(const ADomain: string; ARecord: TDNSRecord): TDNSRecord; override;
    function UpdateRecord(const ADomain: string; ARecord: TDNSRecord): Boolean; override;
    function DeleteRecord(const ADomain, ARecordId: string): Boolean; override;

    property Site: string read FSite write FSite;
  end;

implementation

{ TUbiquitiDNSProvider }

constructor TUbiquitiDNSProvider.Create(const AURL, AUsername, APassword, A2FAToken: string);
begin
  inherited Create('', '');

  FBaseURL := AURL.Trim(['/']);
  FUsername := AUsername;
  FPassword := APassword;
  F2FAToken := A2FAToken;

  FRestClient.BaseURL := FBaseURL;
  FRestClient.ContentType := 'application/json';

  FSite := 'default';

  FDnsListResource := '/v2/api/site/%s/static-dns';
  FDnsItemResource := '/v2/api/site/%s/static-dns/%s';

  if not DoLogin then
    raise EDNSAPIException.Create('UniFi login failed.');
end;

function TUbiquitiDNSProvider.DoLogin: Boolean;
var
  Body: TJSONObject;
  URL: string;
begin
  Result := False;
  URL := '/api/login';

  Body := TJSONObject.Create;
  try
    Body.AddPair('username', FUsername);
    Body.AddPair('password', FPassword);
    Body.AddPair('ubic_2fa_token', F2FAToken);

    FRestRequest.Method := rmPOST;
    FRestRequest.Resource := URL;
    FRestRequest.ClearBody;
    FRestRequest.AddBody(Body.ToJSON, ctAPPLICATION_JSON);
    FRestRequest.Response := FRestResponse;
    FRestRequest.Execute;

    if FRestResponse.StatusCode = 200 then
    begin
      ExtractSessionData(FRestResponse);
      Result := True;
    end;
  finally
    Body.Free;
  end;
end;

procedure TUbiquitiDNSProvider.ExtractSessionData(const Response: TRESTResponse);
var
  I: Integer;
  HeaderName: string;
  HeaderValue: string;
  CookieParts: TArray<string>;
  CookieKV: string;
begin
  FSessionCookie := '';
  FCSRFToken := '';

  for I := 0 to Response.Headers.Count - 1 do
  begin
    HeaderName := Response.Headers.Names[I];
    HeaderValue := Response.Headers.ValueFromIndex[I];

    if SameText(HeaderName, 'Set-Cookie') then
    begin
      CookieParts := HeaderValue.Split([';']);

      if Length(CookieParts) > 0 then
      begin
        CookieKV := Trim(CookieParts[0]);

        if FSessionCookie = '' then
          FSessionCookie := CookieKV
        else
          FSessionCookie := FSessionCookie + '; ' + CookieKV;
      end;
    end;

    if SameText(HeaderName, 'X-CSRF-Token') then
      FCSRFToken := HeaderValue;
  end;
end;

procedure TUbiquitiDNSProvider.SetAuthHeaders;
begin
  FRestRequest.Params.Delete('Authorization');

  if FSessionCookie <> '' then
    FRestRequest.AddParameter('Cookie', FSessionCookie, pkHTTPHEADER, [poDoNotEncode]);

  if FCSRFToken <> '' then
    FRestRequest.AddParameter('X-CSRF-Token', FCSRFToken, pkHTTPHEADER, [poDoNotEncode]);
end;

{ Zones }

function TUbiquitiDNSProvider.ListZones: TObjectList<TDNSZone>;
var
  Z: TDNSZone;
begin
  Result := TObjectList<TDNSZone>.Create(True);

  Z := TDNSZone.Create;
  Z.Id := UNI_SINGLE_ZONE_ID;
  Z.Domain := UNI_SINGLE_ZONE_NAME;

  Result.Add(Z);
end;

function TUbiquitiDNSProvider.GetZone(const ADomain: string): TDNSZone;
begin
  Result := TDNSZone.Create;
  Result.Id := UNI_SINGLE_ZONE_ID;
  Result.Domain := UNI_SINGLE_ZONE_NAME;
end;

function TUbiquitiDNSProvider.CreateZone(const ADomain: string): TDNSZone;
begin
  raise EDNSAPIException.Create('UniFi DNS does not support creating zones.');
end;

function TUbiquitiDNSProvider.DeleteZone(const ADomain: string): Boolean;
begin
  raise EDNSAPIException.Create('UniFi DNS does not support deleting zones.');
end;

{ Records }

function TUbiquitiDNSProvider.ParseRecord(AJson: TJSONObject): TDNSRecord;
var
  LId, LName, LTypeStr, LVal: string;
  ttl: Integer;
  priority: Integer;
begin
  Result := TDNSRecord.Create;
  try
    // ID: "_id"
    if not AJson.TryGetValue<string>('_id', LId) then
      AJson.TryGetValue<string>('id', LId);
    Result.Id := LId;

    // Name / key: "key"
    if not AJson.TryGetValue<string>('key', LName) then
    begin
      // fallback if UniFi ever changes it
      if not AJson.TryGetValue<string>('name', LName) then
        AJson.TryGetValue<string>('hostname', LName);
    end;
    Result.Name := LName;

    // Value / IP: "value"
    LVal := '';
    if not AJson.TryGetValue<string>('value', LVal) then
      if not AJson.TryGetValue<string>('target', LVal) then
        AJson.TryGetValue<string>('ip', LVal);
    Result.Value := LVal;

    // Record type: "record_type"
    if not AJson.TryGetValue<string>('record_type', LTypeStr) then
      AJson.TryGetValue<string>('type', LTypeStr);
    if LTypeStr <> '' then
      Result.RecordType := ParseRecordType(LTypeStr)
    else
      Result.RecordType := drtA;

    // TTL
    if AJson.TryGetValue<Integer>('ttl', ttl) then
      Result.TTL := ttl
    else
      Result.TTL := 0;

    // Priority (for MX; 0 for A)
    if AJson.TryGetValue<Integer>('priority', priority) then
      Result.Priority := priority
    else
      Result.Priority := 0;

    // If your TDNSRecord has Weight/Port, you can also map them here
    // e.g. AJson.TryGetValue<Integer>('weight', Result.Weight);
    //      AJson.TryGetValue<Integer>('port', Result.Port);
  except
    Result.Free;
    raise;
  end;
end;



function TUbiquitiDNSProvider.RecordToJSON(ARecord: TDNSRecord): TJSONObject;
begin
  Result := TJSONObject.Create;
  try
    // Name / key
    Result.AddPair('key', ARecord.Name);

    // Type
    Result.AddPair('record_type', GetRecordTypeString(ARecord.RecordType));

    // Value / IP
    Result.AddPair('value', ARecord.Value);

    // Enabled – UniFi has this, default to true
    Result.AddPair('enabled', TJSONBool.Create(True));

    // TTL
    Result.AddPair('ttl', TJSONNumber.Create(ARecord.TTL));

    // Priority (MX; UniFi has this field even for A)
    Result.AddPair('priority', TJSONNumber.Create(ARecord.Priority));

    // If you later want SRV/CNAME etc you can extend:
    // Result.AddPair('port', TJSONNumber.Create(ARecord.Port));
    // Result.AddPair('weight', TJSONNumber.Create(ARecord.Weight));
  except
    Result.Free;
    raise;
  end;
end;


function TUbiquitiDNSProvider.ParseZone(AJson: TJSONObject): TDNSZone;
begin
  Result := TDNSZone.Create;
  try
    Result.Id := UNI_SINGLE_ZONE_ID;
    Result.Domain := UNI_SINGLE_ZONE_NAME;
  except
    Result.Free;
    raise;
  end;
end;

function TUbiquitiDNSProvider.ListRecords(const ADomain: string;
  ARecordType: TDNSRecordType): TObjectList<TDNSRecord>;
var
  LResponse: TJSONValue;
  LArray: TJSONArray;
  LItem: TJSONValue;
  Rec: TDNSRecord;
  LResource: string;
begin
  Result := TObjectList<TDNSRecord>.Create(True);

  LResource := Format(FDnsListResource, [FSite]);
  LResponse := ExecuteRequest(rmGET, LResource);

  try
    // Case 1: top-level array [ {...}, {...} ]
    if LResponse is TJSONArray then
      LArray := TJSONArray(LResponse)
    // Case 2: { "data": [ {...}, {...} ] }
    else if (LResponse is TJSONObject) and
            TJSONObject(LResponse).TryGetValue<TJSONArray>('data', LArray) then
    begin
      // already have LArray
    end
    else
      Exit; // nothing usable

    for LItem in LArray do
      if LItem is TJSONObject then
      begin
        Rec := ParseRecord(TJSONObject(LItem));

        // If you really want "no filtering" by default, change this logic.
        // Currently: if ARecordType = drtA → ALL records, else only matching type.
        if (ARecordType = drtA) or (Rec.RecordType = ARecordType) then
          Result.Add(Rec)
        else
          Rec.Free;
      end;
  finally
    LResponse.Free;
  end;
end;



function TUbiquitiDNSProvider.GetRecord(const ADomain, ARecordId: string): TDNSRecord;
var
  LResponse: TJSONValue;
  LResource: string;
begin
  if ARecordId = '' then
    raise EDNSException.Create('Record ID required');

  LResource := Format(FDnsItemResource, [FSite, ARecordId]);
  LResponse := ExecuteRequest(rmGET, LResource);

  try
    if LResponse is TJSONObject then
      Result := ParseRecord(TJSONObject(LResponse))
    else
      raise EDNSRecordNotFound.CreateFmt('Record ID "%s" not found', [ARecordId]);
  finally
    LResponse.Free;
  end;
end;

function TUbiquitiDNSProvider.CreateRecord(const ADomain: string; ARecord: TDNSRecord): TDNSRecord;
var
  Payload: TJSONObject;
  LResponse: TJSONValue;
  LResource: string;
begin
  if not ValidateRecord(ARecord) then
    raise EDNSException.Create('Invalid DNS record data');

  Payload := RecordToJSON(ARecord);
  try
    LResource := Format(FDnsListResource, [FSite]);
    LResponse := ExecuteRequest(rmPOST, LResource, Payload);

    if LResponse is TJSONObject then
      Result := ParseRecord(TJSONObject(LResponse))
    else
      raise EDNSAPIException.Create('Unexpected UniFi response for CreateRecord');
  finally
    Payload.Free;
    LResponse.Free;
  end;
end;

function TUbiquitiDNSProvider.UpdateRecord(const ADomain: string; ARecord: TDNSRecord): Boolean;
var
  Payload: TJSONObject;
  LResponse: TJSONValue;
  LResource: string;
begin
  if ARecord.Id = '' then
    raise EDNSException.Create('Record ID required for update');

  if not ValidateRecord(ARecord) then
    raise EDNSException.Create('Invalid DNS record');

  Payload := RecordToJSON(ARecord);
  try
    LResource := Format(FDnsItemResource, [FSite, ARecord.Id]);
    LResponse := ExecuteRequest(rmPUT, LResource, Payload);

    Result := True;
  finally
    Payload.Free;
    LResponse.Free;
  end;
end;

function TUbiquitiDNSProvider.DeleteRecord(const ADomain, ARecordId: string): Boolean;
var
  LResponse: TJSONValue;
  LResource: string;
begin
  if ARecordId = '' then
    raise EDNSException.Create('Record ID required for delete');

  LResource := Format(FDnsItemResource, [FSite, ARecordId]);
  LResponse := ExecuteRequest(rmDELETE, LResource);
  try
    Result := True;
  finally
    LResponse.Free;
  end;
end;

end.

