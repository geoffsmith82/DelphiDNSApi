unit DNS.Bunny;

interface

uses
  System.JSON,
  System.Generics.Collections,
  System.SysUtils,
  System.Classes,
  REST.Client,
  REST.Types,
  DNS.Base;

type
  TBunnyDNSProvider = class(TBaseDNSProvider)
  private
    function RecordTypeToEnumValue(value: TDNSRecordType): Integer;
  protected
    procedure SetAuthHeaders; override;
    function ParseRecord(AJson: TJSONObject): TDNSRecord; override;
    function RecordToJSON(ARecord: TDNSRecord): TJSONObject; override;
    function ParseZone(AJson: TJSONObject): TDNSZone; override;

  public
    constructor Create(const AApiKey: string; const AApiSecret: string = ''); override;

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

type
  TBunnyDNSZone = class(TDNSZone)
  public
    Records: TObjectList<TDNSRecord>;
    constructor Create;
    destructor Destroy; override;
    function Clone: TDNSZone; override;
  end;

function TBunnyDNSZone.Clone: TDNSZone;
var
  i: Integer;
begin
  Result := TBunnyDNSZone.Create;
  Result.Id := Self.Id;
  Result.Domain := Self.Domain;
  Result.CreatedAt := Self.CreatedAt;
  Result.UpdatedAt := Self.UpdatedAt;
  Result.NameServers.Assign(Self.NameServers);
  for i := 0 to Records.Count - 1 do
  begin
    (Result as TBunnyDNSZone).Records.Add((Self as TBunnyDNSZone).Records[i].Clone);
  end;
end;

constructor TBunnyDNSZone.Create;
begin
  inherited Create;
  Records := TObjectList<TDNSRecord>.Create(True);
end;

destructor TBunnyDNSZone.Destroy;
begin
  FreeAndNil(Records);
  inherited;
end;

{ TBunnyDNSProvider }

constructor TBunnyDNSProvider.Create(const AApiKey: string; const AApiSecret: string);
begin
  inherited Create(AApiKey, AApiSecret);
  FRestClient.BaseURL := 'https://api.bunny.net';
end;

procedure TBunnyDNSProvider.SetAuthHeaders;
var
  P: TRESTRequestParameter;
begin
  P := FRestRequest.Params.ParameterByName('AccessKey');
  if P = nil then
    FRestRequest.AddParameter('AccessKey', FApiKey, pkHTTPHEADER, [poDoNotEncode])
  else
  begin
    P.Kind := pkHTTPHEADER;
    P.Options := [poDoNotEncode];
    P.Value := FApiKey;
  end;
end;

function TBunnyDNSProvider.ParseZone(AJson: TJSONObject): TDNSZone;
var
  LZone: TBunnyDNSZone;
  LDomain: string;
  LId: Int64;
  LRecords: TJSONArray;
  LItem: TJSONValue;
begin
  LZone := TBunnyDNSZone.Create;
  try
    if AJson.TryGetValue<Int64>('Id', LId) then
      LZone.Id := LId.ToString;

    if AJson.TryGetValue<string>('Domain', LDomain) then
      LZone.Domain := LDomain;

    if AJson.TryGetValue<TJSONArray>('Records', LRecords) then
    begin
      for LItem in LRecords do
      begin
        if LItem is TJSONObject then
        begin
          LZone.Records.Add(ParseRecord(TJSONObject(LItem)));
        end;
      end;
    end;

    Result := LZone;
  except
    FreeAndNil(LZone);
    raise;
  end;
end;

function TBunnyDNSProvider.ListZones: TObjectList<TDNSZone>;
var
  LResponse: TJSONValue;
  LArray: TJSONArray;
  LItem: TJSONValue;
begin
  Result := TObjectList<TDNSZone>.Create(True);
  LResponse := ExecuteRequest(rmGET, '/dnszone');
  try
    if Assigned(LResponse) then
    begin
      if LResponse.TryGetValue<TJSONArray>('Items', LArray) then
      begin
        for LItem in LArray do
        begin
          if LItem is TJSONObject then
            Result.Add(ParseZone(TJSONObject(LItem)));
        end;
      end;
    end;
  finally
    FreeandNil(LResponse);
  end;
end;


function TBunnyDNSProvider.GetZone(const ADomain: string): TDNSZone;
var
  LZones: TObjectList<TDNSZone>;
  LZone: TDNSZone;
begin
  Result := nil;
  LZones := ListZones;
  try
    for LZone in LZones do
    begin
      if SameText(LZone.Domain, ADomain) then
      begin
        Result := LZones.Extract(LZone);
        Exit;
      end;
    end;
  finally
    FreeAndNil(LZones);
  end;
  raise EDNSZoneNotFound.Create('Zone not found: ' + ADomain);
end;

function TBunnyDNSProvider.CreateZone(const ADomain: string): TDNSZone;
var
  LPayload: TJSONObject;
  LResponse: TJSONObject;
  LId: Int64;
begin
  LPayload := TJSONObject.Create;
  try
    LPayload.AddPair('Domain', ADomain);
    LResponse := ExecuteRequest(rmPOST, '/dnszone', LPayload) as TJSONObject;
    try
      if LResponse.TryGetValue<Int64>('Id', LId) then
        Result := GetZone(ADomain)
      else
        raise EDNSAPIException.Create('Failed to create zone');
    finally
      FreeAndNil(LResponse);
    end;
  finally
    FreeandNil(LPayload);
  end;
end;

function TBunnyDNSProvider.DeleteZone(const ADomain: string): Boolean;
var
  LZone: TDNSZone;
  LResponse: TJSONObject;
begin
  LZone := GetZone(ADomain);
  try
    LResponse := ExecuteRequest(rmDELETE, '/dnszone/' + LZone.Id) as TJSONObject;
    Result := True;
  finally
    FreeAndNil(LZone);
    FreeAndNil(LResponse);
  end;
end;

function TBunnyDNSProvider.ParseRecord(AJson: TJSONObject): TDNSRecord;
var
  LType: string;
  LValue: string;
  LName: string;
  LTTL: Integer;
  LPriority: Integer;
  LWeight, LPort: Integer;
  LId : Int64;
begin
  Result := TDNSRecord.Create;
  try

    if AJson.TryGetValue<Int64>('Id', LId) then
      Result.Id := LId.ToString;
    if AJson.TryGetValue<string>('Name', LName) then
      Result.Name := LName;
    if AJson.TryGetValue<string>('Type', LType) then
      Result.RecordType := ParseRecordType(LType);
    if AJson.TryGetValue<string>('Value', LValue) then
      Result.Value := LValue;
    if AJson.TryGetValue<Integer>('Ttl', LTTL) then
      Result.TTL := LTTL;
    if AJson.TryGetValue<Integer>('Priority', LPriority) then
      Result.Priority := LPriority;
    if AJson.TryGetValue<Integer>('Weight', LWeight) then
      Result.Weight := LWeight;
    if AJson.TryGetValue<Integer>('Port', LPort) then
      Result.Port := LPort;
  except
    FreeandNil(Result);
    raise;
  end;
end;

function TBunnyDNSProvider.RecordTypeToEnumValue(value: TDNSRecordType): Integer;
begin
  case value of
    drtA: Result := 0;
    drtAAAA: Result := 1;
    drtCNAME: Result := 2;
    drtMX: Result := 4;
    drtTXT: Result := 3;
    drtNS: Result := 12;
    drtSOA: Result := -1;
    drtSRV: Result := 8;
    drtPTR: Result := 10;
    drtCAA: Result := 9;
  end;
end;


function TBunnyDNSProvider.RecordToJSON(ARecord: TDNSRecord): TJSONObject;
begin
  Result := TJSONObject.Create;
  try
    Result.AddPair('Type', TJSONNumber.Create(RecordTypeToEnumValue(ARecord.RecordType))); // Bunny uses numeric type codes
    Result.AddPair('Value', ARecord.Value);
    Result.AddPair('Name', ARecord.Name);
    Result.AddPair('Ttl', TJSONNumber.Create(ARecord.TTL));

    if ARecord.RecordType in [drtMX, drtSRV] then
      Result.AddPair('Priority', TJSONNumber.Create(ARecord.Priority));

    if ARecord.RecordType = drtSRV then
    begin
      Result.AddPair('Weight', TJSONNumber.Create(ARecord.Weight));
      Result.AddPair('Port', TJSONNumber.Create(ARecord.Port));
    end;
  except
    FreeandNil(Result);
    raise;
  end;
end;

function TBunnyDNSProvider.ListRecords(const ADomain: string; ARecordType: TDNSRecordType): TObjectList<TDNSRecord>;
var
  LZone: TDNSZone;
  LBunnyZone: TBunnyDNSZone;
  LRecord: TDNSRecord;
begin
  Result := TObjectList<TDNSRecord>.Create(True);
  LZone := GetZone(ADomain);
  try
    if not (LZone is TBunnyDNSZone) then
      Exit;

    LBunnyZone := TBunnyDNSZone(LZone);

    for LRecord in LBunnyZone.Records do
      if (ARecordType = drtA) or (LRecord.RecordType = ARecordType) then
        Result.Add(LRecord.Clone);
  finally
    FreeAndNil(LZone);
  end;
end;

function TBunnyDNSProvider.GetRecord(const ADomain, ARecordId: string): TDNSRecord;
var
  LZone: TDNSZone;
  LBunnyZone: TBunnyDNSZone;
  LRecord: TDNSRecord;
begin
  LZone := GetZone(ADomain);
  try
    if LZone is TBunnyDNSZone then
    begin
      LBunnyZone := TBunnyDNSZone(LZone);
      for LRecord in LBunnyZone.Records do
        if LRecord.Id = ARecordId then
          Exit(LRecord.Clone);
    end;
  finally
    FreeAndNil(LZone);
  end;

  raise EDNSRecordNotFound.Create('Record not found: ' + ARecordId);
end;

function TBunnyDNSProvider.CreateRecord(const ADomain: string; ARecord: TDNSRecord): TDNSRecord;
var
  LZone: TDNSZone;
  LPayload: TJSONObject;
  LResponse: TJSONObject;
  LId: Int64;
begin
  Result := nil;
  if not ValidateRecord(ARecord) then
    raise EDNSException.Create('Invalid record');

  LZone := GetZone(ADomain);
  try
    LPayload := RecordToJSON(ARecord);
    try
      LResponse := ExecuteRequest(rmPUT, '/dnszone/' + LZone.Id + '/records', LPayload) as TJSONObject;
      try
        if LResponse.TryGetValue<Int64>('Id', LId) then
          Result := GetRecord(ADomain, IntToStr(LId))
        else
          raise EDNSAPIException.Create('Record created but no ID returned');
      finally
        FreeandNil(LResponse);
      end;
    finally
      FreeandNil(LPayload);
    end;
  finally
    FreeandNil(LZone);
  end;
end;

function TBunnyDNSProvider.UpdateRecord(const ADomain: string; ARecord: TDNSRecord): Boolean;
var
  LZone: TDNSZone;
  LPayload: TJSONObject;
  LResponse: TJSONObject;
begin
  if ARecord.Id = '' then
    raise EDNSException.Create('Record ID required for update');

  LZone := GetZone(ADomain);
  try
    LPayload := RecordToJSON(ARecord);
    try
      LResponse := ExecuteRequest(rmPOST, '/dnszone/' + LZone.Id + '/records/' + ARecord.Id, LPayload) as TJSONObject;
      Result := True;
    finally
      FreeandNil(LPayload);
      FreeAndNil(LResponse);
    end;
  finally
    FreeandNil(LZone);
  end;
end;

function TBunnyDNSProvider.DeleteRecord(const ADomain, ARecordId: string): Boolean;
var
  LZone: TDNSZone;
  LResponse: TJSONObject;
begin
  LZone := GetZone(ADomain);
  try
    LResponse := ExecuteRequest(rmDELETE, '/dnszone/' + LZone.Id + '/records/' + ARecordId) as TJSONObject;
    Result := True;
  finally
    FreeandNil(LZone);
    FreeAndNil(LResponse);
  end;
end;

end.
