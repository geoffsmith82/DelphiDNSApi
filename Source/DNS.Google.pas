unit DNS.Google;

interface

uses
  System.JSON,
  System.Generics.Collections,
  System.SysUtils,
  System.Classes,
  REST.Types,
  DNS.Base;

type
  TGoogleDNSProvider = class(TBaseDNSProvider)
  private
    FProjectId: string;
  protected
    procedure SetAuthHeaders; override;
    function ParseRecord(AJson: TJSONObject): TDNSRecord; override;
    function RecordToJSON(ARecord: TDNSRecord): TJSONObject; override;
    function ParseZone(AJson: TJSONObject): TDNSZone; override;

    function GetGoogleRecordType(AType: TDNSRecordType): string;
    function ParseGoogleRecordType(const AType: string): TDNSRecordType;
  public
    constructor Create(const AProjectId, AAccessToken: string); reintroduce;

    // Zone (ManagedZone in Google terms) operations
    function ListZones: TObjectList<TDNSZone>; override;
    function GetZone(const ADomain: string): TDNSZone; override;
    function CreateZone(const ADomain: string): TDNSZone; override;
    function DeleteZone(const ADomain: string): Boolean; override;

    // DNS Record operations (via ResourceRecordSets)
    function ListRecords(const ADomain: string; ARecordType: TDNSRecordType = drtA): TObjectList<TDNSRecord>; override;
    function GetRecord(const ADomain, ARecordId: string): TDNSRecord; override;
    function CreateRecord(const ADomain: string; ARecord: TDNSRecord): TDNSRecord; override;
    function UpdateRecord(const ADomain: string; ARecord: TDNSRecord): Boolean; override;
    function DeleteRecord(const ADomain, ARecordId: string): Boolean; override;

    property ProjectId: string read FProjectId;
  end;

implementation

uses
  System.DateUtils, System.NetEncoding;

{ TGoogleDNSProvider }

constructor TGoogleDNSProvider.Create(const AProjectId, AAccessToken: string);
begin
  inherited Create(AAccessToken); // Access token used as API key (OAuth2 Bearer)
  FProjectId := AProjectId;
  FRestClient.BaseURL := 'https://dns.googleapis.com/dns/v1';
end;

procedure TGoogleDNSProvider.SetAuthHeaders;
begin
  FRestRequest.Params.Clear;
  FRestRequest.AddParameter('Authorization', 'Bearer ' + FApiKey, TRESTRequestParameterKind.pkHTTPHEADER, [poDoNotEncode]);
end;

function TGoogleDNSProvider.GetGoogleRecordType(AType: TDNSRecordType): string;
begin
  case AType of
    drtA:     Result := 'A';
    drtAAAA:  Result := 'AAAA';
    drtCNAME: Result := 'CNAME';
    drtMX:    Result := 'MX';
    drtTXT:   Result := 'TXT';
    drtNS:    Result := 'NS';
    drtSOA:   Result := 'SOA';
    drtSRV:   Result := 'SRV';
    drtPTR:   Result := 'PTR';
    drtCAA:   Result := 'CAA';
  else
    Result := 'A';
  end;
end;

function TGoogleDNSProvider.ParseGoogleRecordType(const AType: string): TDNSRecordType;
begin
  if SameText(AType, 'A') then Result := drtA
  else if SameText(AType, 'AAAA') then Result := drtAAAA
  else if SameText(AType, 'CNAME') then Result := drtCNAME
  else if SameText(AType, 'MX') then Result := drtMX
  else if SameText(AType, 'TXT') then Result := drtTXT
  else if SameText(AType, 'NS') then Result := drtNS
  else if SameText(AType, 'SOA') then Result := drtSOA
  else if SameText(AType, 'SRV') then Result := drtSRV
  else if SameText(AType, 'PTR') then Result := drtPTR
  else if SameText(AType, 'CAA') then Result := drtCAA
  else Result := drtA;
end;

function TGoogleDNSProvider.ParseZone(AJson: TJSONObject): TDNSZone;
var
  LName, LCreated: string;
  LDNSName: string;
  LNSArray: TJSONArray;
  I: Integer;
begin
  Result := TDNSZone.Create;
  try
    if AJson.TryGetValue<string>('name', LName) then
      Result.Id := LName;

    if AJson.TryGetValue<string>('dnsName', LDNSName) then
    begin
      Result.Domain := LDNSName;
      if Result.Domain.EndsWith('.') then
        Result.Domain := Result.Domain.Remove(Length(Result.Domain) - 1);
    end;

    if AJson.TryGetValue<string>('creationTime', LCreated) then
      Result.CreatedAt := ISO8601ToDate(LCreated);

    // Name servers
    if AJson.TryGetValue<TJSONArray>('nameServers', LNSArray) then
      for I := 0 to LNSArray.Count - 1 do
        Result.NameServers.Add(LNSArray.Items[I].Value);
  except
    FreeandNil(Result);
    raise;
  end;
end;

function TGoogleDNSProvider.ListZones: TObjectList<TDNSZone>;
var
  LResponse: TJSONValue;
  LZones: TJSONArray;
  LZoneObj: TJSONObject;
  LNextPageToken: string;
begin
  Result := TObjectList<TDNSZone>.Create(True);
  LNextPageToken := '';

  repeat
    if LNextPageToken <> '' then
      LResponse := ExecuteRequest(rmGET, Format('/projects/%s/managedZones?pageToken=%s', [FProjectId, LNextPageToken]))
    else
      LResponse := ExecuteRequest(rmGET, '/projects/' + FProjectId + '/managedZones');

    try
      if Assigned(LResponse) and (LResponse is TJSONObject) then
      begin
        LZones := TJSONObject(LResponse).GetValue<TJSONArray>('managedZones');
        if Assigned(LZones) then
        begin
          for var i := 0 to LZones.Count - 1 do
          begin
            LZoneObj := LZones[i] as TJSONObject;
            if LZoneObj is TJSONObject then
              Result.Add(ParseZone(LZoneObj));
          end;
        end;

        LNextPageToken := '';
        TJSONObject(LResponse).TryGetValue<string>('nextPageToken', LNextPageToken);
      end;
    finally
      FreeandNil(LResponse);
    end;
  until LNextPageToken = '';
end;

function TGoogleDNSProvider.GetZone(const ADomain: string): TDNSZone;
var
  LZones: TObjectList<TDNSZone>;
  LZone: TDNSZone;
begin
  Result := nil;
  LZones := ListZones;
  try
    for var i := 0 to LZones.Count - 1 do
    begin
      LZone := LZones[i];
      if SameText(LZone.Domain, ADomain) or SameText(LZone.Domain, ADomain + '.') then
      begin
        Result := LZone;
        Exit;
      end;
    end;
  finally
    FreeandNil(LZones);
  end;

  raise EDNSZoneNotFound.Create('Zone not found: ' + ADomain);
end;

function TGoogleDNSProvider.CreateZone(const ADomain: string): TDNSZone;
var
  LPayload: TJSONObject;
  LResponse: TJSONObject;
  LDnsName: string;
begin
  LPayload := TJSONObject.Create;
  try
    // Ensure dnsName always ends with a dot (Google requires it)
    if ADomain.EndsWith('.') then
      LDnsName := ADomain
    else
      LDnsName := ADomain + '.';

    LPayload.AddPair('name', TJSONString.Create(ADomain.Replace('.', '-')));
    LPayload.AddPair('dnsName', TJSONString.Create(LDnsName));
    LPayload.AddPair('description', 'Managed by Delphi DNS library');

    LResponse := ExecuteRequest(rmPOST, '/projects/' + FProjectId + '/managedZones', LPayload) as TJSONObject;
    try
      Result := ParseZone(LResponse.GetValue<TJSONObject>('managedZone') as TJSONObject);
    finally
      FreeandNil(LResponse);
    end;
  finally
    FreeandNil(LPayload);
  end;
end;

function TGoogleDNSProvider.DeleteZone(const ADomain: string): Boolean;
var
  LZone: TDNSZone;
begin
  LZone := GetZone(ADomain);
  try
    ExecuteRequest(rmDELETE, '/projects/' + FProjectId + '/managedZones/' + LZone.Id);
    Result := True;
  finally
    FreeandNil(LZone);
  end;
end;

function TGoogleDNSProvider.ParseRecord(AJson: TJSONObject): TDNSRecord;
var
  LName, LTypeStr, LValue: string;
  LTTL: Integer;
  LRrdatas: TJSONArray;
  LParts: TArray<string>;
begin
  Result := TDNSRecord.Create;
  try
    // --- Safe extraction using local variables ---
    if AJson.TryGetValue<string>('name', LName) then
    begin
      Result.Name := LName;
      if Result.Name.EndsWith('.') then
        Result.Name := Result.Name.Remove(Length(Result.Name) - 1);
    end;

    if AJson.TryGetValue<string>('type', LTypeStr) then
      Result.RecordType := ParseGoogleRecordType(LTypeStr);

    if AJson.TryGetValue<Integer>('ttl', LTTL) then
      Result.TTL := LTTL;

    if AJson.TryGetValue<TJSONArray>('rrdatas', LRrdatas) and (LRrdatas.Count > 0) then
    begin
      LValue := LRrdatas.Items[0].Value;

      case Result.RecordType of
        drtTXT:
          begin
            if (LValue.StartsWith('"') and LValue.EndsWith('"')) or
               (LValue.StartsWith('"') and (LRrdatas.Count > 1)) then // multi-string TXT
              LValue := LValue.DeQuotedString;
            Result.Value := LValue;
          end;

        drtMX:
          begin
            LParts := LValue.Split([' ']);
            if Length(LParts) >= 2 then
            begin
              Result.Priority := StrToIntDef(Trim(LParts[0]), 10);
              Result.Value := Trim(LParts[1]);
              if Result.Value.EndsWith('.') then
                Result.Value := Result.Value.Remove(Length(Result.Value) - 1);
            end;
          end;

        drtSRV:
          begin
            LParts := LValue.Split([' ']);
            if Length(LParts) >= 4 then
            begin
              Result.Priority := StrToIntDef(Trim(LParts[0]), 0);
              Result.Weight   := StrToIntDef(Trim(LParts[1]), 0);
              Result.Port     := StrToIntDef(Trim(LParts[2]), 0);
              Result.Value    := Trim(LParts[3]);
              if Result.Value.EndsWith('.') then
                Result.Value := Result.Value.Remove(Length(Result.Value) - 1);
            end;
          end;

        drtCAA:
          begin
            LParts := LValue.Split([' ']);
            if Length(LParts) >= 3 then
            begin
              Result.Flags := StrToIntDef(Trim(LParts[0]), 0);
              Result.Tag := Trim(LParts[1]).DeQuotedString;
              Result.Value := LValue.Substring(
                LParts[0].Length + LParts[1].Length + 2).Trim(['"']);
            end;
          end

        else
          begin
            Result.Value := LValue;
            if Result.Value.EndsWith('.') and (Result.RecordType in [drtCNAME, drtNS, drtPTR]) then
              Result.Value := Result.Value.Remove(Length(Result.Value) - 1);
          end;
      end;
    end;

  except
    FreeandNil(Result);
    raise;
  end;
end;

function TGoogleDNSProvider.RecordToJSON(ARecord: TDNSRecord): TJSONObject;
var
  LData: TJSONArray;
  LValue: string;
begin
  Result := TJSONObject.Create;
  LData := TJSONArray.Create;

  case ARecord.RecordType of
    drtMX:
      LValue := Format('%d %s.', [ARecord.Priority, ARecord.Value]);
    drtTXT:
      LValue := '"' + ARecord.Value + '"';
    drtSRV:
      LValue := Format('%d %d %d %s.', [ARecord.Priority, ARecord.Weight, ARecord.Port, ARecord.Value]);
    drtCAA:
      LValue := Format('%d %s "%s"', [ARecord.Flags, ARecord.Tag, ARecord.Value]);
  else
    LValue := ARecord.Value;
    if (ARecord.RecordType in [drtCNAME, drtNS, drtPTR]) and not LValue.EndsWith('.') then
      LValue := LValue + '.';
  end;

  LData.Add(LValue);

  Result.AddPair('name', ARecord.Name + '.');
  Result.AddPair('type', GetGoogleRecordType(ARecord.RecordType));
  Result.AddPair('ttl', TJSONNumber.Create(ARecord.TTL));
  Result.AddPair('rrdatas', LData);
end;

function TGoogleDNSProvider.ListRecords(const ADomain: string; ARecordType: TDNSRecordType): TObjectList<TDNSRecord>;
var
  LZone: TDNSZone;
  LResponse: TJSONObject;
  LRecordSets: TJSONArray;
  LItem: TJSONObject;
  LRecord: TDNSRecord;
  LTypeFilter: string;
begin
  Result := TObjectList<TDNSRecord>.Create(True);
  LZone := GetZone(ADomain);
  try
    if ARecordType <> drtA then
      LTypeFilter := GetGoogleRecordType(ARecordType)
    else
      LTypeFilter := '';

    LResponse := ExecuteRequest(rmGET,
      Format('/projects/%s/managedZones/%s/rrsets?type=%s', [FProjectId, LZone.Id, LTypeFilter])) as TJSONObject;

    try
      LRecordSets := LResponse.GetValue<TJSONArray>('rrsets');
      if Assigned(LRecordSets) then
      begin
//        for LItem in LRecordSets do
        for var i := 0 to LRecordSets.Count - 1 do
        begin
          LItem := LRecordSets[i] as TJSONObject;
          if LItem is TJSONObject then
          begin
            LRecord := ParseRecord(LItem);
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

function TGoogleDNSProvider.CreateRecord(const ADomain: string; ARecord: TDNSRecord): TDNSRecord;
var
  LZone: TDNSZone;
  LChanges, LAdditions: TJSONObject;
  LResponse: TJSONObject;
begin
  if not ValidateRecord(ARecord) then
    raise EDNSException.Create('Invalid record data');

  LZone := GetZone(ADomain);
  try
    LAdditions := RecordToJSON(ARecord);
    LChanges := TJSONObject.Create;
    LChanges.AddPair('additions', TJSONArray.Create(LAdditions));

    LResponse := ExecuteRequest(rmPOST,
      Format('/projects/%s/managedZones/%s/changes', [FProjectId, LZone.Id]), LChanges) as TJSONObject;

    try
      Result := ParseRecord(LAdditions); // Return what we sent (Google doesn't return full record)
      Result.Id := ''; // Google doesn't use record IDs
    finally
      FreeandNil(LResponse);
      FreeandNil(LChanges);
    end;
  finally
    FreeandNil(LZone);
  end;
end;

function TGoogleDNSProvider.UpdateRecord(const ADomain: string; ARecord: TDNSRecord): Boolean;
var
  LZone: TDNSZone;
  LChanges: TJSONObject;
  LAdditions, LDeletions: TJSONObject;
  LDelRrdatas: TJSONArray;
  LResponse: TJSONValue;
begin
  Result := False;

  if not ValidateRecord(ARecord) then
    raise EDNSException.Create('Invalid record data');

  LZone := GetZone(ADomain);
  try
    LChanges := TJSONObject.Create;
    try
      // --- Build the addition (new version) ---
      LAdditions := RecordToJSON(ARecord);

      // --- Build the deletion (old version - must match exactly except rrdatas = []) ---
      LDeletions := TJSONObject.Create;
      LDeletions.AddPair('name', ARecord.Name + '.');
      LDeletions.AddPair('type', GetGoogleRecordType(ARecord.RecordType));
      LDeletions.AddPair('ttl', TJSONNumber.Create(ARecord.TTL));
      LDelRrdatas := TJSONArray.Create;           // Empty array
      LDeletions.AddPair('rrdatas', LDelRrdatas);

      // --- Combine into changes request ---
      LChanges.AddPair('additions', TJSONArray.Create.Add(LAdditions));
      LChanges.AddPair('deletions', TJSONArray.Create.Add(LDeletions));

      LResponse := ExecuteRequest(rmPOST,
        Format('/projects/%s/managedZones/%s/changes', [FProjectId, LZone.Id]),
        LChanges);

      try
        Result := True;
      finally
        FreeandNil(LResponse);
      end;
    finally
      FreeandNil(LChanges);
    end;
  finally
    FreeandNil(LZone);
  end;
end;


function TGoogleDNSProvider.DeleteRecord(const ADomain, ARecordId: string): Boolean;
var
  LRecords: TObjectList<TDNSRecord>;
  LRecord: TDNSRecord;
  LFound: Boolean;
begin
  Result := False;
  LRecords := ListRecords(ADomain);
  try
    LFound := False;
    for LRecord in LRecords do
    begin
      // Google has no record ID -> match by name + type (and optionally value)
      if (LRecord.Name = ARecordId) or
         (ARecordId = '') and (LRecord.Name = '@') then // allow deleting apex by empty ID
      begin
        LFound := True;

        // Reuse UpdateRecord logic but with empty additions
        var EmptyRec := TDNSRecord.Create;
        try
          EmptyRec.Name := LRecord.Name;
          EmptyRec.RecordType := LRecord.RecordType;
          EmptyRec.TTL := LRecord.TTL;

          var LZone := GetZone(ADomain);
          try
            var LChanges := TJSONObject.Create;
            try
              var LDeletions := TJSONObject.Create;
              LDeletions.AddPair('name', EmptyRec.Name + '.');
              LDeletions.AddPair('type', GetGoogleRecordType(EmptyRec.RecordType));
              LDeletions.AddPair('ttl', TJSONNumber.Create(EmptyRec.TTL));
              LDeletions.AddPair('rrdatas', TJSONArray.Create); // empty!

              LChanges.AddPair('deletions', TJSONArray.Create.Add(LDeletions));
              // no "additions"

              var LResp := ExecuteRequest(rmPOST,
                Format('/projects/%s/managedZones/%s/changes', [FProjectId, LZone.Id]),
                LChanges);
              try
                Result := True;
              finally
                FreeandNil(LResp);
              end;
            finally
              FreeandNil(LChanges);
            end;
          finally
            FreeandNil(LZone);
          end;
        finally
          FreeandNil(EmptyRec);
        end;

        Break;
      end;
    end;

    if not LFound then
      raise EDNSRecordNotFound.Create('Record not found: ' + ARecordId);

  finally
    FreeandNil(LRecords)
  end;
end;


function TGoogleDNSProvider.GetRecord(const ADomain, ARecordId: string): TDNSRecord;
var
  LRecords: TObjectList<TDNSRecord>;
begin
  Result := nil;
  LRecords := ListRecords(ADomain);
  try
    var LRec : TDNSRecord;
    for var i := 0 to LRecords.Count - 1 do
    begin
      LRec := LRecords[i];
      if SameText(LRec.Name, ARecordId) or (ARecordId = '') then
      begin
        Result := LRec.Clone;
        Exit;
      end;
    end;
  finally
    FreeAndNil(LRecords);
  end;
  raise EDNSRecordNotFound.Create('Record not found');
end;

end.
