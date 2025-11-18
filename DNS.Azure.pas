unit DNS.Azure;

interface

uses
  System.SysUtils,
  System.Classes,
  System.JSON,
  System.Generics.Collections,
  REST.Types,
  REST.Client,
  DNS.Base;

type
  TAzureDNSProvider = class(TBaseDNSProvider)
  private
    FSubscriptionId: string;
    FResourceGroup: string;
    FClientId: string;

    FAccessToken: string;
    FTokenExpires: TDateTime;

    function GetAccessToken: string;
    function BasePath: string;
    function RecordTypeToAzurePath(AType: TDNSRecordType): string;

  protected
    procedure SetAuthHeaders; override;

    function ParseRecord(AJson: TJSONObject): TDNSRecord; override;
    function RecordToJSON(ARecord: TDNSRecord): TJSONObject; override;
    function ParseZone(AJson: TJSONObject): TDNSZone; override;

  public
    constructor Create(const ATenantId, AClientId, AClientSecret, ASubscriptionId, AResourceGroup: string); reintroduce;

    // Zones
    function ListZones: TObjectList<TDNSZone>; override;
    function GetZone(const ADomain: string): TDNSZone; override;
    function CreateZone(const ADomain: string): TDNSZone; override;
    function DeleteZone(const ADomain: string): Boolean; override;

    // Records
    function ListRecords(const ADomain: string; ARecordType: TDNSRecordType = drtA): TObjectList<TDNSRecord>; override;
    function GetRecord(const ADomain, ARecordId: string): TDNSRecord; override;
    function CreateRecord(const ADomain: string; ARecord: TDNSRecord): TDNSRecord; override;
    function UpdateRecord(const ADomain: string; ARecord: TDNSRecord): Boolean; override;
    function DeleteRecord(const ADomain, ARecordId: string): Boolean; override;
  end;

implementation

uses
  System.NetEncoding, System.DateUtils;

const
  AZURE_API_VERSION = '2018-05-01';

{===============================================================
   Constructor
===============================================================}
constructor TAzureDNSProvider.Create(const ATenantId, AClientId, AClientSecret, ASubscriptionId, AResourceGroup: string);
begin
  inherited Create(ATenantId, AClientSecret);

  FClientId := AClientId;
  FSubscriptionId := ASubscriptionId;
  FResourceGroup := AResourceGroup;

  FRestClient.BaseURL := 'https://management.azure.com';
  FRestClient.ContentType := 'application/json';
end;

{===============================================================
   Authentication
===============================================================}

function TAzureDNSProvider.GetAccessToken: string;
var
  OAuthClient : TRESTClient;
  OAuthRequest: TRESTRequest;
  OAuthResp   : TRESTResponse;
  LExpiresIn  : Integer;
  LJSON       : TJSONObject;
begin
  // Cached token still valid?
  if (FAccessToken <> '') and (Now < FTokenExpires) then
    Exit(FAccessToken);

  OAuthClient  := TRESTClient.Create(nil);
  OAuthRequest := TRESTRequest.Create(nil);
  OAuthResp    := TRESTResponse.Create(nil);
  try
    OAuthClient.BaseURL := Format('https://login.microsoftonline.com/%s/oauth2/token', [FApiKey]);

    OAuthRequest.Client := OAuthClient;
    OAuthRequest.Response := OAuthResp;

    OAuthRequest.Method := rmPOST;
    OAuthRequest.AddParameter('grant_type', 'client_credentials', pkGETorPOST);
    OAuthRequest.AddParameter('client_id', FClientId, pkGETorPOST);
    OAuthRequest.AddParameter('client_secret', FApiSecret, pkGETorPOST);
    OAuthRequest.AddParameter('resource', 'https://management.azure.com/', pkGETorPOST);
    OAuthRequest.AddParameter('scope', 'https://management.azure.com/.default', pkGETorPOST);

    // Must be application/x-www-form-urlencoded
    OAuthRequest.AddParameter('Content-Type', 'application/x-www-form-urlencoded', TRESTRequestParameterKind.pkHTTPHEADER, [poDoNotEncode]);

    OAuthRequest.Execute;

    if OAuthResp.StatusCode <> 200 then
      raise Exception.CreateFmt('Azure OAuth error %d: %s',
        [OAuthResp.StatusCode, OAuthResp.Content]);

    LJSON := TJSONObject.ParseJSONValue(OAuthResp.Content) as TJSONObject;
    try
      FAccessToken := LJSON.GetValue<string>('access_token');
      LExpiresIn := LJSON.GetValue<Integer>('expires_in');

      // Refresh 2 minutes before expiry
      FTokenExpires := IncSecond(Now, LExpiresIn - 120);
    finally
      FreeAndNil(LJSON);
    end;

    Result := FAccessToken;
  finally
    FreeAndNil(OAuthResp);
    FreeAndNil(OAuthRequest);
    FreeAndNil(OAuthClient);
  end;
end;



procedure TAzureDNSProvider.SetAuthHeaders;
begin
  FRestRequest.Params.Delete('Authorization');
  FRestRequest.AddParameter('Authorization', 'Bearer ' + GetAccessToken, pkHTTPHEADER, [poDoNotEncode]);
end;

function TAzureDNSProvider.BasePath: string;
begin
  Result :=
    '/subscriptions/' + FSubscriptionId +
    '/resourceGroups/' + FResourceGroup +
    '/providers/Microsoft.Network';
end;

{===============================================================
   Zone Parsing
===============================================================}

function TAzureDNSProvider.ParseZone(AJson: TJSONObject): TDNSZone;
var
  Props: TJSONObject;
begin
  Result := TDNSZone.Create;
  try
    Result.Domain := AJson.GetValue<string>('name');
    Result.Id := Result.Domain;

    if AJson.TryGetValue<TJSONObject>('properties', Props) then
    begin
      // nameServers array
      var AJSON2 : TJSONArray;
      if Props.TryGetValue<TJSONArray>('nameServers', AJson2) then
      begin
        for var item in AJson2 as TJSONArray do
          Result.NameServers.Add(item.Value);
      end;
    end;
  except
    FreeAndNil(Result);
    raise;
  end;
end;

{===============================================================
   Record Parsing
===============================================================}

function TAzureDNSProvider.ParseRecord(AJson: TJSONObject): TDNSRecord;
var
  Props: TJSONObject;
  Typ: string;
begin
  Result := TDNSRecord.Create;
  try
    // Azure record ID is composite: recordType/relativeName
    Result.Id := AJson.GetValue<string>('id');
    Result.Name := AJson.GetValue<string>('name');

    Typ := AJson.GetValue<string>('type');
    Typ := Typ.Substring(Typ.LastIndexOf('/')+1); // extract "A", "TXT", etc.

    Result.RecordType := ParseRecordType(Typ);

    Props := AJson.GetValue<TJSONObject>('properties');

    // TTL
    var TTL: Integer;
    if Props.TryGetValue<Integer>('TTL', TTL) then
      Result.TTL := TTL;

    // Value depends on type
    case Result.RecordType of
      drtA:
        Result.Value := Props.GetValue<TJSONArray>('ARecords')[0]
                              .GetValue<string>('ipv4Address');

      drtAAAA:
        Result.Value := Props.GetValue<TJSONArray>('AAAARecords')[0]
                              .GetValue<string>('ipv6Address');

      drtCNAME:
        Result.Value := Props.GetValue<string>('cnameRecord.cname');

      drtTXT:
        Result.Value := Props.GetValue<TJSONArray>('TXTRecords')[0]
                              .GetValue<string>('value');

      drtMX:
        begin
          Result.Priority := Props.GetValue<TJSONArray>('MXRecords')[0]
                                    .GetValue<Integer>('preference');
          Result.Value    := Props.GetValue<TJSONArray>('MXRecords')[0]
                                    .GetValue<string>('exchange');
        end;

      drtSRV:
        begin
          var srv := Props.GetValue<TJSONArray>('SRVRecords')[0] as TJSONObject;
          Result.Priority := srv.GetValue<Integer>('priority');
          Result.Weight   := srv.GetValue<Integer>('weight');
          Result.Port     := srv.GetValue<Integer>('port');
          Result.Value    := srv.GetValue<string>('target');
        end;

      drtCAA:
        begin
          var caa := Props.GetValue<TJSONArray>('CAARecords')[0] as TJSONObject;
          Result.Flags := caa.GetValue<Integer>('flags');
          Result.Tag   := caa.GetValue<string>('tag');
          Result.Value := caa.GetValue<string>('value');
        end;
    end;
  except
    FreeAndNil(Result);
    raise;
  end;
end;

function TAzureDNSProvider.RecordTypeToAzurePath(AType: TDNSRecordType): string;
begin
  Result := GetRecordTypeString(AType).ToUpper;
end;

function TAzureDNSProvider.RecordToJSON(ARecord: TDNSRecord): TJSONObject;
var
  Props: TJSONObject;
  Arr: TJSONArray;
  Rec: TJSONObject;
begin
  Result := TJSONObject.Create;
  Props := TJSONObject.Create;
  Result.AddPair('properties', Props);

  Props.AddPair('TTL', TJSONNumber.Create(ARecord.TTL));

  case ARecord.RecordType of
    drtA:
      begin
        Arr := TJSONArray.Create;
        Rec := TJSONObject.Create;
        Rec.AddPair('ipv4Address', ARecord.Value);
        Arr.Add(Rec);
        Props.AddPair('ARecords', Arr);
      end;

    drtAAAA:
      begin
        Arr := TJSONArray.Create;
        Rec := TJSONObject.Create;
        Rec.AddPair('ipv6Address', ARecord.Value);
        Arr.Add(Rec);
        Props.AddPair('AAAARecords', Arr);
      end;

    drtCNAME:
      Props.AddPair('cnameRecord', TJSONObject.Create.AddPair('cname', ARecord.Value));

    drtTXT:
      begin
        Arr := TJSONArray.Create;
        Rec := TJSONObject.Create;
        Rec.AddPair('value', ARecord.Value);
        Arr.Add(Rec);
        Props.AddPair('TXTRecords', Arr);
      end;

    drtMX:
      begin
        Arr := TJSONArray.Create;
        Rec := TJSONObject.Create;
        Rec.AddPair('preference', TJSONNumber.Create(ARecord.Priority));
        Rec.AddPair('exchange', ARecord.Value);
        Arr.Add(Rec);
        Props.AddPair('MXRecords', Arr);
      end;

    drtSRV:
      begin
        Arr := TJSONArray.Create;
        Rec := TJSONObject.Create;
        Rec.AddPair('priority', TJSONNumber.Create(ARecord.Priority));
        Rec.AddPair('weight',   TJSONNumber.Create(ARecord.Weight));
        Rec.AddPair('port',     TJSONNumber.Create(ARecord.Port));
        Rec.AddPair('target',   ARecord.Value);
        Arr.Add(Rec);
        Props.AddPair('SRVRecords', Arr);
      end;

    drtCAA:
      begin
        Arr := TJSONArray.Create;
        Rec := TJSONObject.Create;
        Rec.AddPair('flags',  TJSONNumber.Create(ARecord.Flags));
        Rec.AddPair('tag',    ARecord.Tag);
        Rec.AddPair('value',  ARecord.Value);
        Arr.Add(Rec);
        Props.AddPair('CAARecords', Arr);
      end;
  end;
end;

{===============================================================
   Zones
===============================================================}

function TAzureDNSProvider.ListZones: TObjectList<TDNSZone>;
var
  LResponse: TJSONValue;
  LArr: TJSONArray;
  item: TJSONValue;
begin
  Result := TObjectList<TDNSZone>.Create(True);

  LResponse := ExecuteRequest(rmGET, BasePath + '/dnsZones?api-version=' + AZURE_API_VERSION);

  try
    if not (LResponse is TJSONObject) then Exit;

    if TJSONObject(LResponse).TryGetValue<TJSONArray>('value', LArr) then
      for item in LArr do
        Result.Add(ParseZone(item as TJSONObject));

  finally
    FreeAndNil(LResponse);
  end;
end;

function TAzureDNSProvider.GetZone(const ADomain: string): TDNSZone;
var
  LResponse: TJSONValue;
  LObj: TJSONObject;
begin
  LResponse := ExecuteRequest(rmGET, BasePath + '/dnsZones/' + ADomain + '?api-version=' + AZURE_API_VERSION);
  try
    if TJSONObject(LResponse).TryGetValue<TJSONObject>('value', LObj) then
      Result := ParseZone(LObj)
    else
      Result := ParseZone(LResponse as TJSONObject);
  finally
    FreeAndNil(LResponse);
  end;
end;

function TAzureDNSProvider.CreateZone(const ADomain: string): TDNSZone;
var
  LBody: TJSONObject;
  LResponse: TJSONValue;
begin
  LBody := TJSONObject.Create;
  try
    LBody.AddPair('location', 'global');

    LResponse := ExecuteRequest(rmPUT, BasePath + '/dnsZones/' + ADomain + '?api-version=' + AZURE_API_VERSION, LBody);

    try
      Result := ParseZone(LResponse as TJSONObject);
    finally
      FreeAndNil(LResponse);
    end;
  finally
    FreeAndNil(LBody);
  end;
end;

function TAzureDNSProvider.DeleteZone(const ADomain: string): Boolean;
var
  LResponse: TJSONValue;
begin
  LResponse := ExecuteRequest(rmDELETE, BasePath + '/dnsZones/' + ADomain + '?api-version=' + AZURE_API_VERSION);

  FreeAndNil(LResponse);
  Result := True;
end;

{===============================================================
   Records
===============================================================}

function TAzureDNSProvider.ListRecords(const ADomain: string; ARecordType: TDNSRecordType): TObjectList<TDNSRecord>;
var
  LResponse: TJSONValue;
  LArr: TJSONArray;
  item: TJSONValue;
begin
  Result := TObjectList<TDNSRecord>.Create(True);

  LResponse := ExecuteRequest(rmGET, BasePath + '/dnsZones/' + ADomain + '/' + RecordTypeToAzurePath(ARecordType) + '?api-version=' + AZURE_API_VERSION);

  try
    if TJSONObject(LResponse).TryGetValue<TJSONArray>('value', LArr) then
      for item in LArr do
        Result.Add(ParseRecord(item as TJSONObject));
  finally
    FreeAndNil(LResponse);
  end;
end;

function TAzureDNSProvider.GetRecord(const ADomain, ARecordId: string): TDNSRecord;
var
  LResponse: TJSONValue;
begin
  // ARecordId = recordType/name
  LResponse := ExecuteRequest(rmGET, BasePath + '/dnsZones/' + ADomain + '/' + ARecordId + '?api-version=' + AZURE_API_VERSION);
  try
    Result := ParseRecord(LResponse as TJSONObject);
  finally
    FreeAndNil(LResponse);
  end;
end;

function TAzureDNSProvider.CreateRecord(const ADomain: string; ARecord: TDNSRecord): TDNSRecord;
var
  LBody: TJSONObject;
  LResponse: TJSONValue;
  Path: string;
begin
  LBody := RecordToJSON(ARecord);
  try
    Path := BasePath + '/dnsZones/' + ADomain + '/' + RecordTypeToAzurePath(ARecord.RecordType) + '/' + ARecord.Name + '?api-version=' + AZURE_API_VERSION;

    LResponse := ExecuteRequest(rmPUT, Path, LBody);
    try
      Result := ParseRecord(LResponse as TJSONObject);
    finally
      FreeAndNil(LResponse);
    end;
  finally
    FreeAndNil(LBody);
  end;
end;

function TAzureDNSProvider.UpdateRecord(const ADomain: string; ARecord: TDNSRecord): Boolean;
var
  LBody: TJSONObject;
  LResponse: TJSONValue;
  Path: string;
begin
  LBody := RecordToJSON(ARecord);
  try
    Path := BasePath + '/dnsZones/' + ADomain + '/' + RecordTypeToAzurePath(ARecord.RecordType) + '/' + ARecord.Name + '?api-version=' + AZURE_API_VERSION;

    LResponse := ExecuteRequest(rmPUT, Path, LBody);
    FreeAndNil(LResponse);

    Result := True;
  finally
    FreeAndNil(LBody);
  end;
end;

function TAzureDNSProvider.DeleteRecord(const ADomain, ARecordId: string): Boolean;
var
  LResponse: TJSONValue;
begin
  LResponse := ExecuteRequest(rmDELETE, BasePath + '/dnsZones/' + ADomain + '/' + ARecordId + '?api-version=' + AZURE_API_VERSION);

  FreeAndNil(LResponse);
  Result := True;
end;

end.

