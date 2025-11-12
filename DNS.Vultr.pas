unit DNS.Vultr;

interface

uses
  System.JSON,
  System.Generics.Collections,
  System.SysUtils,
  System.Classes,
  REST.Types,
  DNS.Base;

type
  TVultrDNSProvider = class(TBaseDNSProvider)
  protected
    procedure SetAuthHeaders; override;
    function ParseRecord(AJson: TJSONObject): TDNSRecord; override;
    function RecordToJSON(ARecord: TDNSRecord): TJSONObject; override;
    function ParseZone(AJson: TJSONObject): TDNSZone; override;

    function GetVultrRecordType(AType: TDNSRecordType): string;
    function ParseVultrRecordType(const AType: string): TDNSRecordType;
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

    // Vultr specific methods
    function GetSOA(const ADomain: string): TJSONObject;
    function UpdateSOA(const ADomain, ANSPrimary, AEmail: string): Boolean;
    function GetDNSSec(const ADomain: string): TJSONArray;
    function EnableDNSSec(const ADomain: string): Boolean;
    function DisableDNSSec(const ADomain: string): Boolean;
  end;

implementation

uses
  System.DateUtils,
  REST.Client;

{ TVultrDNSProvider }

constructor TVultrDNSProvider.Create(const AApiKey: string; const AApiSecret: string);
begin
  inherited Create(AApiKey, AApiSecret);
  FRestClient.BaseURL := 'https://api.vultr.com/v2';
  FRestClient.ContentType := 'application/json';
end;

procedure TVultrDNSProvider.SetAuthHeaders;
begin
  // Clear existing auth params and add Bearer token
  FRestRequest.Params.Delete('Authorization');
  FRestRequest.AddParameter('Authorization', 'Bearer ' + FApiKey,
    TRESTRequestParameterKind.pkHTTPHEADER, [poDoNotEncode]);
end;

function TVultrDNSProvider.GetVultrRecordType(AType: TDNSRecordType): string;
begin
  case AType of
    drtA: Result := 'A';
    drtAAAA: Result := 'AAAA';
    drtCNAME: Result := 'CNAME';
    drtMX: Result := 'MX';
    drtTXT: Result := 'TXT';
    drtNS: Result := 'NS';
    drtSRV: Result := 'SRV';
    drtCAA: Result := 'CAA';
    drtSOA: Result := 'SOA';
    drtPTR: Result := 'PTR';
  else
    Result := 'A';
  end;
end;

function TVultrDNSProvider.ParseVultrRecordType(const AType: string): TDNSRecordType;
begin
  if SameText(AType, 'A') then Result := drtA
  else if SameText(AType, 'AAAA') then Result := drtAAAA
  else if SameText(AType, 'CNAME') then Result := drtCNAME
  else if SameText(AType, 'MX') then Result := drtMX
  else if SameText(AType, 'TXT') then Result := drtTXT
  else if SameText(AType, 'NS') then Result := drtNS
  else if SameText(AType, 'SRV') then Result := drtSRV
  else if SameText(AType, 'CAA') then Result := drtCAA
  else if SameText(AType, 'SOA') then Result := drtSOA
  else if SameText(AType, 'PTR') then Result := drtPTR
  else Result := drtA;
end;

function TVultrDNSProvider.ParseRecord(AJson: TJSONObject): TDNSRecord;
var
  LType: string;
  LData: string;
  Lid: string;
  LName: string;
  LTTL: Integer;
  LPriority: Integer;
  LTag: string;
  LFlags: Integer;
  LWeight: Integer;
  LPort: Integer;
begin
  Result := TDNSRecord.Create;
  try
    // Vultr uses "id" for record identifier
    if AJson.TryGetValue<string>('id', Lid) then
      Result.Id := Lid;

    // Vultr uses "name" for the subdomain
    if AJson.TryGetValue<string>('name', LName) then
      Result.Name := LName;

    // Parse record type
    if AJson.TryGetValue<string>('type', LType) then
      Result.RecordType := ParseVultrRecordType(LType);

    // Vultr uses "data" for the record value
    if AJson.TryGetValue<string>('data', LData) then
      Result.Value := LData;

    // TTL
    if AJson.TryGetValue<Integer>('ttl', LTTL) then
      Result.TTL := LTTL;

    // Priority (for MX and SRV records)
    if AJson.TryGetValue<Integer>('priority', LPriority) then
      Result.Priority := LPriority;

    // SRV specific fields
    if Result.RecordType = drtSRV then
    begin
      if AJson.TryGetValue<Integer>('weight', LWeight) then
        Result.Weight := LWeight;
      if AJson.TryGetValue<Integer>('port', LPort) then
        Result.Port := LPort;
    end;

    // CAA specific fields
    if Result.RecordType = drtCAA then
    begin
      if AJson.TryGetValue<Integer>('flags', LFlags) then
        Result.Flags := LFlags;

      if AJson.TryGetValue<string>('tag', LTag) then
        Result.Tag := LTag;
    end;
  except
    Result.Free;
    raise;
  end;
end;

function TVultrDNSProvider.RecordToJSON(ARecord: TDNSRecord): TJSONObject;
begin
  Result := TJSONObject.Create;
  try
    // Required fields for Vultr API
    Result.AddPair('name', ARecord.Name);
    Result.AddPair('type', GetVultrRecordType(ARecord.RecordType));
    Result.AddPair('data', ARecord.Value);

    // TTL (optional, Vultr defaults to 3600 if not specified)
    if ARecord.TTL > 0 then
      Result.AddPair('ttl', TJSONNumber.Create(ARecord.TTL));

    // Priority for MX and SRV records
    if ARecord.RecordType in [drtMX, drtSRV] then
      Result.AddPair('priority', TJSONNumber.Create(ARecord.Priority));

    // SRV specific fields
    if ARecord.RecordType = drtSRV then
    begin
      Result.AddPair('weight', TJSONNumber.Create(ARecord.Weight));
      Result.AddPair('port', TJSONNumber.Create(ARecord.Port));
    end;

    // CAA specific fields
    if ARecord.RecordType = drtCAA then
    begin
      Result.AddPair('flags', TJSONNumber.Create(ARecord.Flags));
      Result.AddPair('tag', ARecord.Tag);
    end;
  except
    Result.Free;
    raise;
  end;
end;

function TVultrDNSProvider.ParseZone(AJson: TJSONObject): TDNSZone;
var
  LDateStr: string;
  LNS: string;
  LDomain: string;
begin
  Result := TDNSZone.Create;
  try
    // Vultr uses "domain" as the zone identifier
    if AJson.TryGetValue<string>('domain', LDomain) then
    begin
      Result.Domain := LDomain;
      Result.Id := LDomain; // Vultr uses domain name as ID
    end;

    // Parse date created
    if AJson.TryGetValue<string>('date_created', LDateStr) then
      Result.CreatedAt := ISO8601ToDate(LDateStr);

    // DNS server (Vultr doesn't return multiple NS in zone list)
    if AJson.TryGetValue<string>('dns_server', LNS) then
      Result.NameServers.Add(LNS);
  except
    Result.Free;
    raise;
  end;
end;

function TVultrDNSProvider.ListZones: TObjectList<TDNSZone>;
var
  LResponse: TJSONValue;
  LDomains: TJSONArray;
  LDomain: TJSONValue;
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
    LDomains := nil;

    // Vultr uses pagination with per_page and page
    while LFetched < LTotal do
    begin
      LResource := Format('/domains?per_page=100&page=%d', [LPage]);
      LResponse := ExecuteRequest(rmGET, LResource);
      try
        if Assigned(LResponse) and (LResponse is TJSONObject) then
        begin
          // Get the domains array
          LDomains := TJSONObject(LResponse).GetValue('domains') as TJSONArray;

          // Get pagination metadata
          if TJSONObject(LResponse).TryGetValue<TJSONObject>('meta', LMeta) then
            LMeta.TryGetValue<Integer>('total', LTotal);

          if Assigned(LDomains) then
          begin
            for LDomain in LDomains do
            begin
              if LDomain is TJSONObject then
              begin
                LZone := ParseZone(TJSONObject(LDomain));
                Result.Add(LZone);
                Inc(LFetched);
              end;
            end;
          end;
        end;


      Inc(LPage);

      // Break if we've fetched all or if the last response had no domains
      if not Assigned(LDomains) then
        break;
      if (LDomains.Count = 0) then
        Break;
      finally
        LResponse.Free;
      end;
    end;
  except
    Result.Free;
    raise;
  end;
end;

function TVultrDNSProvider.GetZone(const ADomain: string): TDNSZone;
var
  LResponse: TJSONValue;
  LDomainObj: TJSONObject;
begin
  Result := nil;
  LResponse := ExecuteRequest(rmGET, '/domains/' + ADomain);
  try
    if Assigned(LResponse) and (LResponse is TJSONObject) then
    begin
      // Vultr returns the domain in a "domain" object
      if TJSONObject(LResponse).TryGetValue<TJSONObject>('domain', LDomainObj) then
        Result := ParseZone(LDomainObj)
      else
        Result := ParseZone(TJSONObject(LResponse));
    end;
  finally
    LResponse.Free;
  end;
end;

function TVultrDNSProvider.CreateZone(const ADomain: string): TDNSZone;
var
  LPayload: TJSONObject;
  LResponse: TJSONValue;
  LDomainObj: TJSONObject;
begin
  Result := nil;
  LPayload := TJSONObject.Create;
  try
    LPayload.AddPair('domain', ADomain);
    // Optionally add IP for default A record
    // LPayload.AddPair('ip', '0.0.0.0');

    LResponse := ExecuteRequest(rmPOST, '/domains', LPayload);
    try
      if Assigned(LResponse) and (LResponse is TJSONObject) then
      begin
        if TJSONObject(LResponse).TryGetValue<TJSONObject>('domain', LDomainObj) then
          Result := ParseZone(LDomainObj)
        else
          Result := ParseZone(TJSONObject(LResponse));
      end;
    finally
      LResponse.Free;
    end;
  finally
    LPayload.Free;
  end;
end;

function TVultrDNSProvider.DeleteZone(const ADomain: string): Boolean;
var
  LResponse: TJSONValue;
begin
  LResponse := ExecuteRequest(rmDELETE, '/domains/' + ADomain);
  try
    Result := True; // Vultr returns 204 No Content on success
  finally
    LResponse.Free;
  end;
end;

function TVultrDNSProvider.ListRecords(const ADomain: string; ARecordType: TDNSRecordType): TObjectList<TDNSRecord>;
var
  LResponse: TJSONValue;
  LRecords: TJSONArray;
  LRecord: TJSONValue;
  LDNSRecord: TDNSRecord;
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
    LRecords := nil;

    while LFetched < LTotal do
    begin
      // Build resource URL with pagination
      LResource := Format('/domains/%s/records?per_page=100&page=%d', [ADomain, LPage]);

      // Add type filter if specific type requested
      if ARecordType <> drtA then
        LResource := LResource + '&type=' + GetVultrRecordType(ARecordType);

      LResponse := ExecuteRequest(rmGET, LResource);
      try
        if Assigned(LResponse) and (LResponse is TJSONObject) then
        begin
          // Get the records array
          LRecords := TJSONObject(LResponse).GetValue('records') as TJSONArray;

          // Get pagination metadata
          if TJSONObject(LResponse).TryGetValue<TJSONObject>('meta', LMeta) then
            LMeta.TryGetValue<Integer>('total', LTotal);

          if Assigned(LRecords) then
          begin
            for LRecord in LRecords do
            begin
              if LRecord is TJSONObject then
              begin
                LDNSRecord := ParseRecord(TJSONObject(LRecord));

                // Filter by type if needed
                if (ARecordType = drtA) or (LDNSRecord.RecordType = ARecordType) then
                  Result.Add(LDNSRecord)
                else
                  LDNSRecord.Free;

                Inc(LFetched);
              end;
            end;
          end;
        end;


      Inc(LPage);

      // Break if we've fetched all or if the last response had no records
      if (not Assigned(LRecords)) or (LRecords.Count = 0) then
        Break;
      finally
        LResponse.Free;
      end;
    end;
  except
    Result.Free;
    raise;
  end;
end;

function TVultrDNSProvider.GetRecord(const ADomain, ARecordId: string): TDNSRecord;
var
  LResponse: TJSONValue;
  LRecordObj: TJSONObject;
  LResource: string;
begin
  Result := nil;

  LResource := Format('/domains/%s/records/%s', [ADomain, ARecordId]);
  LResponse := ExecuteRequest(rmGET, LResource);
  try
    if Assigned(LResponse) and (LResponse is TJSONObject) then
    begin
      // Vultr returns the record in a "record" object
      if TJSONObject(LResponse).TryGetValue<TJSONObject>('record', LRecordObj) then
        Result := ParseRecord(LRecordObj)
      else
        Result := ParseRecord(TJSONObject(LResponse));
    end;
  finally
    LResponse.Free;
  end;
end;

function TVultrDNSProvider.CreateRecord(const ADomain: string;
  ARecord: TDNSRecord): TDNSRecord;
var
  LPayload: TJSONObject;
  LResponse: TJSONValue;
  LRecordObj: TJSONObject;
  LResource: string;
begin
  Result := nil;

  // Validate record before sending
  if not ValidateRecord(ARecord) then
    raise EDNSException.Create('Invalid DNS record data');

  LPayload := RecordToJSON(ARecord);
  try
    LResource := '/domains/' + ADomain + '/records';
    LResponse := ExecuteRequest(rmPOST, LResource, LPayload);
    try
      if Assigned(LResponse) and (LResponse is TJSONObject) then
      begin
        if TJSONObject(LResponse).TryGetValue<TJSONObject>('record', LRecordObj) then
          Result := ParseRecord(LRecordObj)
        else
          Result := ParseRecord(TJSONObject(LResponse));
      end;
    finally
      LResponse.Free;
    end;
  finally
    LPayload.Free;
  end;
end;

function TVultrDNSProvider.UpdateRecord(const ADomain: string; ARecord: TDNSRecord): Boolean;
var
  LPayload: TJSONObject;
  LResponse: TJSONValue;
  LResource: string;
begin
  Result := False;

  if ARecord.Id = '' then
    raise EDNSException.Create('Record ID is required for update');

  // Validate record before sending
  if not ValidateRecord(ARecord) then
    raise EDNSException.Create('Invalid DNS record data');

  LPayload := RecordToJSON(ARecord);
  try
    LResource := Format('/domains/%s/records/%s', [ADomain, ARecord.Id]);
    // Vultr uses PATCH for record updates
    LResponse := ExecuteRequest(rmPATCH, LResource, LPayload);
    try
      Result := True; // Vultr returns 204 No Content on success
    finally
      LResponse.Free;
    end;
  finally
    LPayload.Free;
  end;
end;

function TVultrDNSProvider.DeleteRecord(const ADomain, ARecordId: string): Boolean;
var
  LResponse: TJSONValue;
  LResource: string;
begin
  LResource := Format('/domains/%s/records/%s', [ADomain, ARecordId]);
  LResponse := ExecuteRequest(rmDELETE, LResource);
  try
    Result := True; // Vultr returns 204 No Content on success
  finally
    LResponse.Free;
  end;
end;

function TVultrDNSProvider.GetSOA(const ADomain: string): TJSONObject;
var
  LResponse: TJSONValue;
begin
  Result := nil;
  LResponse := ExecuteRequest(rmGET, '/domains/' + ADomain + '/soa');
  if Assigned(LResponse) and (LResponse is TJSONObject) then
    Result := TJSONObject(LResponse)
  else
  begin
    LResponse.Free;
    raise EDNSException.Create('Failed to get SOA record');
  end;
end;

function TVultrDNSProvider.UpdateSOA(const ADomain, ANSPrimary, AEmail: string): Boolean;
var
  LPayload: TJSONObject;
  LResponse: TJSONValue;
begin
  Result := False;
  LPayload := TJSONObject.Create;
  try
    LPayload.AddPair('nsprimary', ANSPrimary);
    LPayload.AddPair('email', AEmail);

    LResponse := ExecuteRequest(rmPATCH, '/domains/' + ADomain + '/soa', LPayload);
    try
      Result := True;
    finally
      LResponse.Free;
    end;
  finally
    LPayload.Free;
  end;
end;

function TVultrDNSProvider.GetDNSSec(const ADomain: string): TJSONArray;
var
  LResponse: TJSONValue;
begin
  Result := nil;
  LResponse := ExecuteRequest(rmGET, '/domains/' + ADomain + '/dnssec');

  if Assigned(LResponse) then
  begin
    if LResponse is TJSONArray then
      Result := TJSONArray(LResponse)
    else if LResponse is TJSONObject then
    begin
      // Check if the response contains a dnssec array
      if TJSONObject(LResponse).TryGetValue<TJSONArray>('dnssec', Result) then
        Result := TJSONArray(Result.Clone as TJSONArray);
      LResponse.Free;
    end
    else
      LResponse.Free;
  end;
end;

function TVultrDNSProvider.EnableDNSSec(const ADomain: string): Boolean;
var
  LResponse: TJSONValue;
begin
  LResponse := ExecuteRequest(rmPUT, '/domains/' + ADomain + '/dnssec');
  try
    Result := True;
  finally
    LResponse.Free;
  end;
end;

function TVultrDNSProvider.DisableDNSSec(const ADomain: string): Boolean;
var
  LResponse: TJSONValue;
begin
  LResponse := ExecuteRequest(rmDELETE, '/domains/' + ADomain + '/dnssec');
  try
    Result := True;
  finally
    LResponse.Free;
  end;
end;

end.
