unit DNS.DigitalOcean;

interface

uses
  System.SysUtils,
  System.Classes,
  System.JSON,
  System.Generics.Collections,
  REST.Types,
  DNS.Base;

type
  TDigitalOceanDNSProvider = class(TBaseDNSProvider)
  protected
    // TBaseDNSProvider hooks
    procedure SetAuthHeaders; override;
    function ParseRecord(AJson: TJSONObject): TDNSRecord; override;
    function RecordToJSON(ARecord: TDNSRecord): TJSONObject; override;
    function ParseZone(AJson: TJSONObject): TDNSZone; override;

  public
    constructor Create(const AApiKey: string; const AApiSecret: string = ''); override;

    // Zone/Domain operations
    function ListZones: TObjectList<TDNSZone>; override;
    function GetZone(const ADomain: string): TDNSZone; override;
    function CreateZone(const ADomain: string): TDNSZone; override;
    function DeleteZone(const ADomain: string): Boolean; override;

    // DNS Record operations
    function ListRecords(const ADomain: string;
      ARecordType: TDNSRecordType = drtA): TObjectList<TDNSRecord>; override;
    function GetRecord(const ADomain, ARecordId: string): TDNSRecord; override;
    function CreateRecord(const ADomain: string; ARecord: TDNSRecord): TDNSRecord; override;
    function UpdateRecord(const ADomain: string; ARecord: TDNSRecord): Boolean; override;
    function DeleteRecord(const ADomain, ARecordId: string): Boolean; override;
  end;

implementation

uses
  System.DateUtils;

{ TDigitalOceanDNSProvider }

constructor TDigitalOceanDNSProvider.Create(const AApiKey, AApiSecret: string);
begin
  inherited Create(AApiKey, AApiSecret);

  // DigitalOcean API v2 base URL
  FRestClient.BaseURL := 'https://api.digitalocean.com/v2';
  FRestClient.ContentType := 'application/json';
end;

procedure TDigitalOceanDNSProvider.SetAuthHeaders;
begin
  // Clear existing auth header and add Bearer token
  FRestRequest.Params.Delete('Authorization');
  FRestRequest.AddParameter(
    'Authorization',
    'Bearer ' + FApiKey,
    TRESTRequestParameterKind.pkHTTPHEADER,
    [poDoNotEncode]
  );
end;

{ ---------- Zone / Domain parsing ---------- }

function TDigitalOceanDNSProvider.ParseZone(AJson: TJSONObject): TDNSZone;
var
  LName: string;
  LZoneFile: string;
  LLine: string;
  LParts: TArray<string>;
  I: Integer;
begin
  Result := TDNSZone.Create;
  try
    // DigitalOcean domain object uses "name" as the domain
    if AJson.TryGetValue<string>('name', LName) then
    begin
      Result.Domain := LName;
      // DigitalOcean doesn't have a separate numeric ID for domains;
      // use the domain name as the logical Id (same pattern as Vultr).
      Result.Id := LName;
    end;

    // DO domain object typically has: name, ttl, zone_file.
    // We don't currently have a TTL field on TDNSZone.
    // If "zone_file" is present, we can try to extract NS records from it.
    if AJson.TryGetValue<string>('zone_file', LZoneFile) then
    begin
      for LLine in LZoneFile.Split([sLineBreak]) do
      begin
        // crude BIND-style parsing, looking for NS records:
        // e.g. "example.com.   1800    IN  NS  ns1.digitalocean.com."
        LParts := LLine.Split([' ', #9], TStringSplitOptions.ExcludeEmpty);
        if Length(LParts) >= 4 then
        begin
          // Look for "NS" as the type field; it's usually at index 3 or 2
          for I := 0 to High(LParts) do
          begin
            if SameText(LParts[I], 'NS') then
            begin
              if I + 1 <= High(LParts) then
                Result.NameServers.Add(LParts[I+1]);
              Break;
            end;
          end;
        end;
      end;
    end;

    // DigitalOcean domain object does not expose created_at/updated_at
    // for DNS domains in the public API, so we leave CreatedAt/UpdatedAt at 0.
  except
    FreeAndNil(Result);
    raise;
  end;
end;

{ ---------- Record parsing / serialization ---------- }

function TDigitalOceanDNSProvider.ParseRecord(AJson: TJSONObject): TDNSRecord;
var
  LId: string;
  LName: string;
  LTypeStr: string;
  LData: string;
  LTTL: Integer;
  LPriority: Integer;
  LWeight: Integer;
  LPort: Integer;
  LFlags: Integer;
  LTag: string;
begin
  Result := TDNSRecord.Create;
  try
    // "id" - unique identifier
    if AJson.TryGetValue<string>('id', LId) then
      Result.Id := LId;

    // "name" - host/subdomain (may be '@' for apex)
    if AJson.TryGetValue<string>('name', LName) then
      Result.Name := LName;

    // "type" - e.g. "A", "MX", "TXT" ...
    if AJson.TryGetValue<string>('type', LTypeStr) then
      Result.RecordType := ParseRecordType(LTypeStr)
    else
      Result.RecordType := drtA; // fallback

    // "data" - common value field for most types
    if AJson.TryGetValue<string>('data', LData) then
      Result.Value := LData;

    // "ttl" - time to live
    if AJson.TryGetValue<Integer>('ttl', LTTL) then
      Result.TTL := LTTL;

    // Priority for MX and SRV
    if (Result.RecordType in [drtMX, drtSRV]) and
       AJson.TryGetValue<Integer>('priority', LPriority) then
      Result.Priority := LPriority;

    // SRV-specific
    if Result.RecordType = drtSRV then
    begin
      if AJson.TryGetValue<Integer>('weight', LWeight) then
        Result.Weight := LWeight;
      if AJson.TryGetValue<Integer>('port', LPort) then
        Result.Port := LPort;
    end;

    // CAA-specific
    if Result.RecordType = drtCAA then
    begin
      if AJson.TryGetValue<Integer>('flags', LFlags) then
        Result.Flags := LFlags;
      if AJson.TryGetValue<string>('tag', LTag) then
        Result.Tag := LTag;
    end;
  except
    FreeAndNil(Result);
    raise;
  end;
end;

function TDigitalOceanDNSProvider.RecordToJSON(ARecord: TDNSRecord): TJSONObject;
begin
  Result := TJSONObject.Create;
  try
    // DO expects standard DNS fields: type, name, data, ttl, priority, weight, port, flags, tag.
    Result.AddPair('type', GetRecordTypeString(ARecord.RecordType));
    Result.AddPair('name', ARecord.Name);
    Result.AddPair('data', ARecord.Value);

    if ARecord.TTL > 0 then
      Result.AddPair('ttl', TJSONNumber.Create(ARecord.TTL));

    if ARecord.RecordType in [drtMX, drtSRV] then
      Result.AddPair('priority', TJSONNumber.Create(ARecord.Priority));

    if ARecord.RecordType = drtSRV then
    begin
      Result.AddPair('weight', TJSONNumber.Create(ARecord.Weight));
      Result.AddPair('port', TJSONNumber.Create(ARecord.Port));
    end;

    if ARecord.RecordType = drtCAA then
    begin
      Result.AddPair('flags', TJSONNumber.Create(ARecord.Flags));
      Result.AddPair('tag', ARecord.Tag);
      // For CAA, ARecord.Value still goes in "data"
    end;
  except
    FreeAndNil(Result);
    raise;
  end;
end;

{ ---------- Zone / Domain operations ---------- }

function TDigitalOceanDNSProvider.ListZones: TObjectList<TDNSZone>;
var
  LResponse: TJSONValue;
  LDomains: TJSONArray;
  LDomainVal: TJSONValue;
  LZone: TDNSZone;
  LPage: Integer;
  LTotal, LFetched: Integer;
  LMeta: TJSONObject;
  LResource: string;
begin
  Result := TObjectList<TDNSZone>.Create(True);
  try
    LPage := 1;
    LFetched := 0;
    LTotal := MaxInt;

    // Simple pagination loop, similar to TVultrDNSProvider
    while LFetched < LTotal do
    begin
      LResource := Format('/domains?page=%d&per_page=100', [LPage]);
      LResponse := ExecuteRequest(rmGET, LResource);
      try
        if Assigned(LResponse) and (LResponse is TJSONObject) then
        begin
          LDomains := TJSONObject(LResponse).GetValue<TJSONArray>('domains');

          // pagination meta.total, if provided
          if TJSONObject(LResponse).TryGetValue<TJSONObject>('meta', LMeta) then
            LMeta.TryGetValue<Integer>('total', LTotal);

          if Assigned(LDomains) then
          begin
            for LDomainVal in LDomains do
            begin
              if LDomainVal is TJSONObject then
              begin
                LZone := ParseZone(TJSONObject(LDomainVal));
                Result.Add(LZone);
                Inc(LFetched);
              end;
            end;

            // break if the page was empty
            if LDomains.Count = 0 then
              Break;
          end
          else
            Break;
        end
        else
          Break;
      finally
        FreeAndNil(LResponse);
      end;

      Inc(LPage);
      if LPage > 1000 then // guard
        Break;
    end;
  except
    FreeAndNil(Result);
    raise;
  end;
end;

function TDigitalOceanDNSProvider.GetZone(const ADomain: string): TDNSZone;
var
  LResponse: TJSONValue;
  LDomainObj: TJSONObject;
begin
  Result := nil;
  LResponse := ExecuteRequest(rmGET, '/domains/' + ADomain);
  try
    if Assigned(LResponse) and (LResponse is TJSONObject) then
    begin
      if TJSONObject(LResponse).TryGetValue<TJSONObject>('domain', LDomainObj) then
        Result := ParseZone(LDomainObj)
      else
        raise EDNSZoneNotFound.CreateFmt('Domain "%s" not found', [ADomain]);
    end
    else
      raise EDNSAPIException.Create('Unexpected response when getting domain');
  finally
    FreeAndNil(LResponse);
  end;
end;

function TDigitalOceanDNSProvider.CreateZone(const ADomain: string): TDNSZone;
var
  LBody: TJSONObject;
  LResponse: TJSONValue;
  LDomainObj: TJSONObject;
begin
  // NOTE: DigitalOcean also supports an "ip_address" attribute to create an A record
  // at the same time. TBaseDNSProvider.CreateZone only passes ADomain, so we omit it.
  LBody := TJSONObject.Create;
  try
    LBody.AddPair('name', ADomain);

    LResponse := ExecuteRequest(rmPOST, '/domains', LBody);
    try
      if Assigned(LResponse) and (LResponse is TJSONObject) and
         TJSONObject(LResponse).TryGetValue<TJSONObject>('domain', LDomainObj) then
        Result := ParseZone(LDomainObj)
      else
        raise EDNSAPIException.Create('Failed to create domain');
    finally
      FreeAndNil(LResponse);
    end;
  finally
    FreeAndNil(LBody);
  end;
end;

function TDigitalOceanDNSProvider.DeleteZone(const ADomain: string): Boolean;
var
  LResponse: TJSONValue;
begin
  LResponse := ExecuteRequest(rmDELETE, '/domains/' + ADomain);
  try
    // DO returns 204 No Content on success; if ExecuteRequest didn't raise,
    // we assume success.
    Result := True;
  finally
    FreeAndNil(LResponse);
  end;
end;

{ ---------- Record operations ---------- }

function TDigitalOceanDNSProvider.ListRecords(const ADomain: string;
  ARecordType: TDNSRecordType): TObjectList<TDNSRecord>;
var
  LResponse: TJSONValue;
  LRecordsArr: TJSONArray;
  LRecordVal: TJSONValue;
  LRec: TDNSRecord;
  LPage: Integer;
  LTotal, LFetched: Integer;
  LMeta: TJSONObject;
  LResource: string;
begin
  Result := TObjectList<TDNSRecord>.Create(True);
  try
    LPage := 1;
    LFetched := 0;
    LTotal := MaxInt;

    while LFetched < LTotal do
    begin
      LResource := Format('/domains/%s/records?page=%d&per_page=100', [ADomain, LPage]);

      // DigitalOcean docs don't mention a ?type= filter, so we fetch all
      // and filter client-side instead of adding a query parameter.

      LResponse := ExecuteRequest(rmGET, LResource);
      try
        if Assigned(LResponse) and (LResponse is TJSONObject) then
        begin
          LRecordsArr := TJSONObject(LResponse).GetValue<TJSONArray>('domain_records');

          if TJSONObject(LResponse).TryGetValue<TJSONObject>('meta', LMeta) then
            LMeta.TryGetValue<Integer>('total', LTotal);

          if Assigned(LRecordsArr) then
          begin
            for LRecordVal in LRecordsArr do
            begin
              if LRecordVal is TJSONObject then
              begin
                LRec := ParseRecord(TJSONObject(LRecordVal));

                if (ARecordType = drtA) or (LRec.RecordType = ARecordType) then
                begin
                  Result.Add(LRec);
                  Inc(LFetched);
                end
                else
                  FreeAndNil(LRec);
              end;
            end;

            if LRecordsArr.Count = 0 then
              Break;
          end
          else
            Break;
        end
        else
          Break;
      finally
        FreeAndNil(LResponse);
      end;

      Inc(LPage);
      if LPage > 1000 then
        Break;
    end;
  except
    FreeAndNil(Result);
    raise;
  end;
end;

function TDigitalOceanDNSProvider.GetRecord(const ADomain, ARecordId: string): TDNSRecord;
var
  LResponse: TJSONValue;
  LObj: TJSONObject;
begin
  Result := nil;
  LResponse := ExecuteRequest(rmGET,
    Format('/domains/%s/records/%s', [ADomain, ARecordId]));
  try
    if Assigned(LResponse) and (LResponse is TJSONObject) and
       TJSONObject(LResponse).TryGetValue<TJSONObject>('domain_record', LObj) then
      Result := ParseRecord(LObj)
    else
      raise EDNSRecordNotFound.CreateFmt(
        'Record "%s" not found in domain "%s"', [ARecordId, ADomain]);
  finally
    FreeAndNil(LResponse);
  end;
end;

function TDigitalOceanDNSProvider.CreateRecord(const ADomain: string;
  ARecord: TDNSRecord): TDNSRecord;
var
  LBody: TJSONObject;
  LResponse: TJSONValue;
  LObj: TJSONObject;
begin
  LBody := RecordToJSON(ARecord);
  try
    LResponse := ExecuteRequest(rmPOST,
      Format('/domains/%s/records', [ADomain]), LBody);
    try
      if Assigned(LResponse) and (LResponse is TJSONObject) and
         TJSONObject(LResponse).TryGetValue<TJSONObject>('domain_record', LObj) then
        Result := ParseRecord(LObj)
      else
        raise EDNSAPIException.Create('Failed to create DNS record');
    finally
      FreeAndNil(LResponse);
    end;
  finally
    FreeAndNil(LBody);
  end;
end;

function TDigitalOceanDNSProvider.UpdateRecord(const ADomain: string;
  ARecord: TDNSRecord): Boolean;
var
  LBody: TJSONObject;
  LResponse: TJSONValue;
  LResource: string;
begin
  if ARecord.Id = '' then
    raise EDNSException.Create('Record Id must be set for update');

  LBody := RecordToJSON(ARecord);
  try
    LResource := Format('/domains/%s/records/%s', [ADomain, ARecord.Id]);
    LResponse := ExecuteRequest(rmPUT, LResource, LBody);
    try
      // If ExecuteRequest did not raise, we consider the update successful.
      Result := True;
    finally
      FreeAndNil(LResponse);
    end;
  finally
    FreeAndNil(LBody);
  end;
end;

function TDigitalOceanDNSProvider.DeleteRecord(const ADomain, ARecordId: string): Boolean;
var
  LResponse: TJSONValue;
  LResource: string;
begin
  LResource := Format('/domains/%s/records/%s', [ADomain, ARecordId]);
  LResponse := ExecuteRequest(rmDELETE, LResource);
  try
    // DO returns 204 No Content on success.
    Result := True;
  finally
    FreeAndNil(LResponse);
  end;
end;

end.

