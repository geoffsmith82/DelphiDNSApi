unit DNS.Bunny;

interface

uses
  System.JSON,
  System.Generics.Collections,
  System.SysUtils,
  System.Classes,
  REST.Types,
  DNS.Base;

type
  TBunnyDNSProvider = class(TBaseDNSProvider)
  protected
    procedure SetAuthHeaders; override;
    function ParseRecord(AJson: TJSONObject): TDNSRecord; override;
    function RecordToJSON(ARecord: TDNSRecord): TJSONObject; override;
    function ParseZone(AJson: TJSONObject): TDNSZone; override;

    function GetBunnyRecordType(AType: TDNSRecordType): string;
    function ParseBunnyRecordType(const AType: string): TDNSRecordType;
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

{ TBunnyDNSProvider }

constructor TBunnyDNSProvider.Create(const AApiKey: string; const AApiSecret: string);
begin
  inherited Create(AApiKey, AApiSecret);
  FRestClient.BaseURL := 'https://api.bunny.net';
end;

procedure TBunnyDNSProvider.SetAuthHeaders;
begin
  FRestRequest.Params.Clear;
  FRestRequest.AddParameter('AccessKey', FApiKey, pkHTTPHEADER, [poDoNotEncode]);
end;

function TBunnyDNSProvider.GetBunnyRecordType(AType: TDNSRecordType): string;
begin
  case AType of
    drtA:     Result := 'A';
    drtAAAA:  Result := 'AAAA';
    drtCNAME: Result := 'CNAME';
    drtMX:    Result := 'MX';
    drtTXT:   Result := 'TXT';
    drtNS:    Result := 'NS';
    drtSRV:   Result := 'SRV';
    drtCAA:   Result := 'CAA';
    drtPTR:   Result := 'PTR';
  else
    Result := 'A';
  end;
end;

function TBunnyDNSProvider.ParseBunnyRecordType(const AType: string): TDNSRecordType;
begin
  if SameText(AType, 'A') then Result := drtA
  else if SameText(AType, 'AAAA') then Result := drtAAAA
  else if SameText(AType, 'CNAME') then Result := drtCNAME
  else if SameText(AType, 'MX') then Result := drtMX
  else if SameText(AType, 'TXT') then Result := drtTXT
  else if SameText(AType, 'NS') then Result := drtNS
  else if SameText(AType, 'SRV') then Result := drtSRV
  else if SameText(AType, 'CAA') then Result := drtCAA
  else if SameText(AType, 'PTR') then Result := drtPTR
  else Result := drtA;
end;

function TBunnyDNSProvider.ParseZone(AJson: TJSONObject): TDNSZone;
var
  LDomain: string;
  LId: Int64;
begin
  Result := TDNSZone.Create;
  try
    if AJson.TryGetValue<Int64>('Id', LId) then
      Result.Id := IntToStr(LId);

    if AJson.TryGetValue<string>('Domain', LDomain) then
      Result.Domain := LDomain;

    // Bunny doesn't return creation/update dates in list, but single GET does
  except
    FreeandNil(Result);
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
    if Assigned(LResponse) and (LResponse is TJSONArray) then
    begin
      LArray := TJSONArray(LResponse);
      for LItem in LArray do
      begin
        if LItem is TJSONObject then
          Result.Add(ParseZone(TJSONObject(LItem)));
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
        Result := LZone;
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
begin
  LZone := GetZone(ADomain);
  try
    ExecuteRequest(rmDELETE, '/dnszone/' + LZone.Id);
    Result := True;
  finally
    FreeAndNil(LZone);
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
      Result.RecordType := ParseBunnyRecordType(LType);
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

function TBunnyDNSProvider.RecordToJSON(ARecord: TDNSRecord): TJSONObject;
begin
  Result := TJSONObject.Create;
  try
    Result.AddPair('Type', Ord(ARecord.RecordType)); // Bunny uses numeric type codes
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
  LResponse: TJSONValue;
  LArray: TJSONArray;
  LItem: TJSONValue;
  LRecord: TDNSRecord;
begin
  Result := TObjectList<TDNSRecord>.Create(True);
  LZone := GetZone(ADomain);
  try
    LResponse := ExecuteRequest(rmGET, '/dnszone/' + LZone.Id + '/records');
    try
      if Assigned(LResponse) and (LResponse is TJSONArray) then
      begin
        LArray := TJSONArray(LResponse);
        for LItem in LArray do
        begin
          if LItem is TJSONObject then
          begin
            LRecord := ParseRecord(TJSONObject(LItem));
            if (ARecordType = drtA) or (LRecord.RecordType = ARecordType) then
              Result.Add(LRecord)
            else
              FreeandNil(LRecord);
          end;
        end;
      end;
    finally
      FreeandNil(LResponse);
    end;
  finally
    FreeandNil(LZone);
  end;
end;

function TBunnyDNSProvider.GetRecord(const ADomain, ARecordId: string): TDNSRecord;
var
  LZone: TDNSZone;
  LResponse: TJSONObject;
begin
  Result := nil;
  LZone := GetZone(ADomain);
  try
    LResponse := ExecuteRequest(rmGET, '/dnszone/' + LZone.Id + '/records/' + ARecordId) as TJSONObject;
    try
      Result := ParseRecord(LResponse);
    finally
      FreeandNil(LResponse);
    end;
  finally
    FreeandNil(LZone);
  end;
end;

function TBunnyDNSProvider.CreateRecord(const ADomain: string; ARecord: TDNSRecord): TDNSRecord;
var
  LZone: TDNSZone;
  LPayload: TJSONObject;
  LResponse: TJSONObject;
  LId: Int64;
begin
  if not ValidateRecord(ARecord) then
    raise EDNSException.Create('Invalid record');

  LZone := GetZone(ADomain);
  try
    LPayload := RecordToJSON(ARecord);
    try
      LResponse := ExecuteRequest(rmPOST, '/dnszone/' + LZone.Id + '/records', LPayload) as TJSONObject;
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
begin
  if ARecord.Id = '' then
    raise EDNSException.Create('Record ID required for update');

  LZone := GetZone(ADomain);
  try
    LPayload := RecordToJSON(ARecord);
    try
      ExecuteRequest(rmPUT, '/dnszone/' + LZone.Id + '/records/' + ARecord.Id, LPayload);
      Result := True;
    finally
      FreeandNil(LPayload);
    end;
  finally
    FreeandNil(LZone);
  end;
end;

function TBunnyDNSProvider.DeleteRecord(const ADomain, ARecordId: string): Boolean;
var
  LZone: TDNSZone;
begin
  LZone := GetZone(ADomain);
  try
    ExecuteRequest(rmDELETE, '/dnszone/' + LZone.Id + '/records/' + ARecordId);
    Result := True;
  finally
    FreeandNil(LZone);
  end;
end;

end.
