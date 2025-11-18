unit DNS.Cloudflare;

interface

uses
  System.SysUtils,
  System.Classes,
  System.JSON,
  System.Generics.Collections,
  REST.Types,
  DNS.Base;

type
  TCloudflareDNSProvider = class(TBaseDNSProvider)
  protected
    procedure SetAuthHeaders; override;
    function ParseRecord(AJson: TJSONObject): TDNSRecord; override;
    function RecordToJSON(ARecord: TDNSRecord): TJSONObject; override;
    function ParseZone(AJson: TJSONObject): TDNSZone; override;

    function GetZoneId(const ADomain: string): string;
  public
    constructor Create(const AApiKey: string; const AApiSecret: string = ''); override;

    // Zone/Domain operations
    function ListZones: TObjectList<TDNSZone>; override;
    function GetZone(const ADomain: string): TDNSZone; override;
    function CreateZone(const ADomain: string): TDNSZone; override;
    function DeleteZone(const ADomain: string): Boolean; override;

    // DNS Record operations
    function ListRecords(const ADomain: string; ARecordType: TDNSRecordType = drtA): TObjectList<TDNSRecord>; override;
    function GetRecord(const ADomain, ARecordId: string): TDNSRecord; override;
    function CreateRecord(const ADomain: string; ARecord: TDNSRecord): TDNSRecord; override;
    function UpdateRecord(const ADomain: string; ARecord: TDNSRecord): Boolean; override;
    function DeleteRecord(const ADomain, ARecordId: string): Boolean; override;
  end;

implementation

uses
  System.DateUtils;

{ TCloudflareDNSProvider }

constructor TCloudflareDNSProvider.Create(const AApiKey, AApiSecret: string);
begin
  inherited Create(AApiKey, AApiSecret);
  // Cloudflare v4 API base URL
  FBaseUrl := 'https://api.cloudflare.com/client/v4';
  if Assigned(FRestClient) then
    FRestClient.BaseURL := FBaseUrl;
end;

procedure TCloudflareDNSProvider.SetAuthHeaders;
begin
  // Cloudflare recommends API tokens via Authorization: Bearer header
  FRestRequest.Params.Delete('Authorization');
  FRestRequest.AddParameter('Authorization', 'Bearer ' + FApiKey, TRESTRequestParameterKind.pkHTTPHEADER, [poDoNotEncode]
  );
end;

function TCloudflareDNSProvider.ParseRecord(AJson: TJSONObject): TDNSRecord;
var
  LId, LName, LType, LContent: string;
  LTTL, LPriority, LFlags, LWeight, LPort: Integer;
  LTag: string;
  LDataObj: TJSONObject;
begin
  Result := TDNSRecord.Create;
  try
    // Identifier
    if AJson.TryGetValue<string>('id', LId) then
      Result.Id := LId;

    // Name (Cloudflare typically returns the FQDN here)
    if AJson.TryGetValue<string>('name', LName) then
      Result.Name := LName;

    // Type -> TDNSRecordType
    if AJson.TryGetValue<string>('type', LType) then
      Result.RecordType := ParseRecordType(LType);

    // Primary value/content
    if AJson.TryGetValue<string>('content', LContent) then
      Result.Value := LContent;

    // TTL
    if AJson.TryGetValue<Integer>('ttl', LTTL) then
      Result.TTL := LTTL;

    // Priority (MX and some SRV)
    if AJson.TryGetValue<Integer>('priority', LPriority) then
      Result.Priority := LPriority;

    // Extended data for SRV/CAA stored in "data" object
    if AJson.TryGetValue<TJSONObject>('data', LDataObj) then
    begin
      case Result.RecordType of
        drtCAA:
          begin
            if LDataObj.TryGetValue<Integer>('flags', LFlags) then
              Result.Flags := LFlags;
            if LDataObj.TryGetValue<string>('tag', LTag) then
              Result.Tag := LTag;

            // Some Cloudflare APIs put the CAA value here as "value"
            if LDataObj.TryGetValue<string>('value', LContent) then
              Result.Value := LContent;
          end;

        drtSRV:
          begin
            if LDataObj.TryGetValue<Integer>('weight', LWeight) then
              Result.Weight := LWeight;
            if LDataObj.TryGetValue<Integer>('port', LPort) then
              Result.Port := LPort;
            if LDataObj.TryGetValue<Integer>('priority', LPriority) then
              Result.Priority := LPriority;
          end;
      end;
    end;
  except
    FreeAndNil(Result);
    raise;
  end;
end;

function TCloudflareDNSProvider.RecordToJSON(ARecord: TDNSRecord): TJSONObject;
var
  LData: TJSONObject;
begin
  Result := TJSONObject.Create;
  try
    // Required fields
    Result.AddPair('name', ARecord.Name);
    Result.AddPair('type', GetRecordTypeString(ARecord.RecordType));
    Result.AddPair('content', ARecord.Value);

    // TTL: Cloudflare uses 1 for "automatic", but we treat 0 as "don't send"
    if ARecord.TTL > 0 then
      Result.AddPair('ttl', TJSONNumber.Create(ARecord.TTL));

    // Priority mainly for MX and SRV
    if ARecord.RecordType in [drtMX, drtSRV] then
      Result.AddPair('priority', TJSONNumber.Create(ARecord.Priority));

    // Extended fields for SRV
    if ARecord.RecordType = drtSRV then
    begin
      LData := TJSONObject.Create;
      try
        LData.AddPair('weight', TJSONNumber.Create(ARecord.Weight));
        LData.AddPair('port', TJSONNumber.Create(ARecord.Port));
        LData.AddPair('priority', TJSONNumber.Create(ARecord.Priority));
        Result.AddPair('data', LData);
      except
        FreeAndNil(LData);
        raise;
      end;
    end
    else if ARecord.RecordType = drtCAA then
    begin
      // Cloudflare supports structured CAA data via "data"
      LData := TJSONObject.Create;
      try
        LData.AddPair('flags', TJSONNumber.Create(ARecord.Flags));
        LData.AddPair('tag', ARecord.Tag);
        // Keep value in both "value" and "content" for compatibility
        LData.AddPair('value', ARecord.Value);
        Result.AddPair('data', LData);
      except
        FreeAndNil(LData);
        raise;
      end;
    end;
  except
    FreeAndNil(Result);
    raise;
  end;
end;

function TCloudflareDNSProvider.ParseZone(AJson: TJSONObject): TDNSZone;
var
  LDateStr: string;
  LNS: TJSONValue;
  LArray: TJSONArray;
begin
  Result := TDNSZone.Create;
  try
    // Cloudflare uses "id" as zone identifier and "name" for the domain
    if AJson.TryGetValue<string>('id', LDateStr) then
      Result.Id := LDateStr;

    if AJson.TryGetValue<string>('name', LDateStr) then
      Result.Domain := LDateStr;

    // Timestamps
    if AJson.TryGetValue<string>('created_on', LDateStr) then
      Result.CreatedAt := ISO8601ToDate(LDateStr);

    if AJson.TryGetValue<string>('modified_on', LDateStr) then
      Result.UpdatedAt := ISO8601ToDate(LDateStr);

    // Name servers array
    LArray := AJson.GetValue('name_servers') as TJSONArray;
    if Assigned(LArray) then
      for LNS in LArray do
        if LNS is TJSONString then
          Result.NameServers.Add(TJSONString(LNS).Value);
  except
    FreeAndNil(Result);
    raise;
  end;
end;

function TCloudflareDNSProvider.GetZoneId(const ADomain: string): string;
var
  LZone: TDNSZone;
begin
  LZone := GetZone(ADomain);
  try
    if Assigned(LZone) then
      Result := LZone.Id
    else
      Result := '';
  finally
    FreeAndNil(LZone);
  end;
end;

function TCloudflareDNSProvider.ListZones: TObjectList<TDNSZone>;
var
  LResponse: TJSONValue;
  LZones: TJSONArray;
  LZoneVal: TJSONValue;
  LZone: TDNSZone;
  LPage, LTotalPages: Integer;
  LResource: string;
  LInfo: TJSONObject;
begin
  Result := TObjectList<TDNSZone>.Create(True);
  try
    LPage := 1;
    LTotalPages := MaxInt;

    while LPage <= LTotalPages do
    begin
      LResource := Format('/zones?page=%d&per_page=50', [LPage]);
      LResponse := ExecuteRequest(rmGET, LResource);
      try
        if Assigned(LResponse) and (LResponse is TJSONObject) then
        begin
          LZones := TJSONObject(LResponse).GetValue('result') as TJSONArray;
          if TJSONObject(LResponse).TryGetValue<TJSONObject>('result_info', LInfo) then
            LInfo.TryGetValue<Integer>('total_pages', LTotalPages);

          if Assigned(LZones) then
          begin
            for LZoneVal in LZones do
              if LZoneVal is TJSONObject then
              begin
                LZone := ParseZone(TJSONObject(LZoneVal));
                Result.Add(LZone);
              end;

            if LZones.Count = 0 then
              Break;
          end
          else
            Break;
        end
        else
          Break;
      finally
        LResponse.Free;
      end;

      Inc(LPage);
    end;
  except
    Result.Free;
    raise;
  end;
end;

function TCloudflareDNSProvider.GetZone(const ADomain: string): TDNSZone;
var
  LResponse: TJSONValue;
  LZones: TJSONArray;
  LZoneObj: TJSONObject;
  LResource: string;
begin
  Result := nil;
  LResource := Format('/zones?name=%s&per_page=1', [ADomain]);
  LResponse := ExecuteRequest(rmGET, LResource);
  try
    if Assigned(LResponse) and (LResponse is TJSONObject) then
    begin
      LZones := TJSONObject(LResponse).GetValue('result') as TJSONArray;
      if Assigned(LZones) and (LZones.Count > 0) and (LZones.Items[0] is TJSONObject) then
      begin
        LZoneObj := TJSONObject(LZones.Items[0]);
        Result := ParseZone(LZoneObj);
      end;
    end;

    if not Assigned(Result) then
      raise EDNSZoneNotFound.CreateFmt('Zone "%s" not found in Cloudflare account', [ADomain]);
  finally
    LResponse.Free;
  end;
end;

function TCloudflareDNSProvider.CreateZone(const ADomain: string): TDNSZone;
var
  LPayload: TJSONObject;
  LResponse: TJSONValue;
  LZoneObj: TJSONObject;
begin
  LPayload := TJSONObject.Create;
  try
    // Minimal required payload
    LPayload.AddPair('name', ADomain);
    LPayload.AddPair('jump_start', TJSONBool.Create(False));

    LResponse := ExecuteRequest(rmPOST, '/zones', LPayload);
  finally
    LPayload.Free;
  end;

  try
    if Assigned(LResponse) and (LResponse is TJSONObject) then
    begin
      LZoneObj := TJSONObject(LResponse).GetValue('result') as TJSONObject;
      if Assigned(LZoneObj) then
        Exit(ParseZone(LZoneObj));
    end;
    raise EDNSAPIException.Create('Unexpected response when creating Cloudflare zone');
  finally
    LResponse.Free;
  end;
end;

function TCloudflareDNSProvider.DeleteZone(const ADomain: string): Boolean;
var
  LZoneId: string;
  LResponse: TJSONValue;
  LObj: TJSONObject;
  LSuccess: Boolean;
begin
  LZoneId := GetZoneId(ADomain);
  if LZoneId = '' then
    raise EDNSZoneNotFound.CreateFmt('Zone "%s" not found', [ADomain]);

  LResponse := ExecuteRequest(rmDELETE, Format('/zones/%s', [LZoneId]));
  try
    Result := False;
    if Assigned(LResponse) and (LResponse is TJSONObject) then
    begin
      LObj := TJSONObject(LResponse);
      if LObj.TryGetValue<Boolean>('success', LSuccess) then
        Result := LSuccess;
    end;
  finally
    LResponse.Free;
  end;
end;

function TCloudflareDNSProvider.ListRecords(const ADomain: string;
  ARecordType: TDNSRecordType): TObjectList<TDNSRecord>;
var
  LResponse: TJSONValue;
  LRecords: TJSONArray;
  LRecVal: TJSONValue;
  LRecord: TDNSRecord;
  LZoneId: string;
  LPage, LTotalPages: Integer;
  LResource: string;
  LInfo: TJSONObject;
begin
  Result := TObjectList<TDNSRecord>.Create(True);
  try
    LZoneId := GetZoneId(ADomain);
    if LZoneId = '' then
      raise EDNSZoneNotFound.CreateFmt('Zone "%s" not found', [ADomain]);

    LPage := 1;
    LTotalPages := MaxInt;

    while LPage <= LTotalPages do
    begin
      LResource := Format('/zones/%s/dns_records?page=%d&per_page=100', [LZoneId, LPage]);

      // Add type filter if specific type requested (drtA used as "all" sentinel)
      if ARecordType <> drtA then
        LResource := LResource + '&type=' + GetRecordTypeString(ARecordType);

      LResponse := ExecuteRequest(rmGET, LResource);
      try
        if Assigned(LResponse) and (LResponse is TJSONObject) then
        begin
          LRecords := TJSONObject(LResponse).GetValue('result') as TJSONArray;
          if TJSONObject(LResponse).TryGetValue<TJSONObject>('result_info', LInfo) then
            LInfo.TryGetValue<Integer>('total_pages', LTotalPages);

          if Assigned(LRecords) then
          begin
            for LRecVal in LRecords do
              if LRecVal is TJSONObject then
              begin
                LRecord := ParseRecord(TJSONObject(LRecVal));

                // Extra guard in case API-side filter is not enough
                if (ARecordType = drtA) or (LRecord.RecordType = ARecordType) then
                  Result.Add(LRecord)
                else
                  LRecord.Free;
              end;

            if LRecords.Count = 0 then
              Break;
          end
          else
            Break;
        end
        else
          Break;
      finally
        LResponse.Free;
      end;

      Inc(LPage);
    end;
  except
    Result.Free;
    raise;
  end;
end;

function TCloudflareDNSProvider.GetRecord(const ADomain, ARecordId: string): TDNSRecord;
var
  LZoneId: string;
  LResponse: TJSONValue;
  LObj, LRecObj: TJSONObject;
begin
  LZoneId := GetZoneId(ADomain);
  if LZoneId = '' then
    raise EDNSZoneNotFound.CreateFmt('Zone "%s" not found', [ADomain]);

  LResponse := ExecuteRequest(rmGET, Format('/zones/%s/dns_records/%s', [LZoneId, ARecordId]));
  try
    if Assigned(LResponse) and (LResponse is TJSONObject) then
    begin
      LObj := TJSONObject(LResponse);
      LRecObj := LObj.GetValue('result') as TJSONObject;
      if Assigned(LRecObj) then
        Exit(ParseRecord(LRecObj));
    end;

    raise EDNSRecordNotFound.CreateFmt('Record "%s" not found in zone "%s"', [ARecordId, ADomain]);
  finally
    LResponse.Free;
  end;
end;

function TCloudflareDNSProvider.CreateRecord(const ADomain: string;
  ARecord: TDNSRecord): TDNSRecord;
var
  LZoneId: string;
  LPayload: TJSONObject;
  LResponse: TJSONValue;
  LObj, LRecObj: TJSONObject;
begin
  LZoneId := GetZoneId(ADomain);
  if LZoneId = '' then
    raise EDNSZoneNotFound.CreateFmt('Zone "%s" not found', [ADomain]);

  LPayload := RecordToJSON(ARecord);
  try
    LResponse := ExecuteRequest(
      rmPOST,
      Format('/zones/%s/dns_records', [LZoneId]),
      LPayload
    );
  finally
    LPayload.Free;
  end;

  try
    if Assigned(LResponse) and (LResponse is TJSONObject) then
    begin
      LObj := TJSONObject(LResponse);
      LRecObj := LObj.GetValue('result') as TJSONObject;
      if Assigned(LRecObj) then
        Exit(ParseRecord(LRecObj));
    end;

    raise EDNSAPIException.Create('Unexpected response when creating Cloudflare DNS record');
  finally
    LResponse.Free;
  end;
end;

function TCloudflareDNSProvider.UpdateRecord(const ADomain: string;
  ARecord: TDNSRecord): Boolean;
var
  LZoneId: string;
  LPayload: TJSONObject;
  LResponse: TJSONValue;
  LObj: TJSONObject;
  LSuccess: Boolean;
begin
  LZoneId := GetZoneId(ADomain);
  if LZoneId = '' then
    raise EDNSZoneNotFound.CreateFmt('Zone "%s" not found', [ADomain]);

  if ARecord.Id = '' then
    raise EDNSAPIException.Create('Cannot update Cloudflare DNS record without an Id');

  LPayload := RecordToJSON(ARecord);
  try
    LResponse := ExecuteRequest(
      rmPUT,
      Format('/zones/%s/dns_records/%s', [LZoneId, ARecord.Id]),
      LPayload
    );
  finally
    LPayload.Free;
  end;

  try
    Result := False;
    if Assigned(LResponse) and (LResponse is TJSONObject) then
    begin
      LObj := TJSONObject(LResponse);
      if LObj.TryGetValue<Boolean>('success', LSuccess) then
        Result := LSuccess;
    end;
  finally
    LResponse.Free;
  end;
end;

function TCloudflareDNSProvider.DeleteRecord(const ADomain, ARecordId: string): Boolean;
var
  LZoneId: string;
  LResponse: TJSONValue;
  LObj: TJSONObject;
  LSuccess: Boolean;
begin
  LZoneId := GetZoneId(ADomain);
  if LZoneId = '' then
    raise EDNSZoneNotFound.CreateFmt('Zone "%s" not found', [ADomain]);

  LResponse := ExecuteRequest(
    rmDELETE,
    Format('/zones/%s/dns_records/%s', [LZoneId, ARecordId])
  );

  try
    Result := False;
    if Assigned(LResponse) and (LResponse is TJSONObject) then
    begin
      LObj := TJSONObject(LResponse);
      if LObj.TryGetValue<Boolean>('success', LSuccess) then
        Result := LSuccess;
    end;
  finally
    LResponse.Free;
  end;
end;

end.

