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
  Xml.XMLIntf,
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

    function EnsureTrailingDot(const S: string): string;
    function StripTrailingDot(const S: string): string;
    function NormalizeRecordFqdn(const ARecordName, AZoneDomain: string): string;
    function NormalizeRecordId(const ARecordName, AZoneDomain: string): string;

    function FindChildByLocalName(const AParent: IXMLNode; const ALocalName: string): IXMLNode;
    function GetChildTextByLocalName(const AParent: IXMLNode; const ALocalName: string): string;

    function ExecuteRequestXML(const AMethod: TRESTRequestMethod; const AResource: string; const ABody: string = ''): IXMLDocument;

    function AwsUriEncode(const S: string): string;
    function CanonicalizeQueryString(const Query: string): string;

    function HmacSHA256(const AKey: TBytes; const AData: string): TBytes;
    function CalculateSignature(const ASecretKey, ADate, ARegion, AService, AStringToSign: string): string;
    function BuildCanonicalRequest(const AMethod: string; const ACanonicalUri, ACanonicalQuery, ACanonicalHeaders, ASignedHeaders, APayloadHash: string): string;
    function BuildStringToSign(const ARequestDateTime, ACredentialScope, AHashedCanonicalRequest: string): string;

    procedure SignRequest(const AMethod: TRESTRequestMethod; const AResource: string);
  protected
    procedure SetAuthHeaders; override;

    function GetRecordTypeString(AType: TDNSRecordType): string; override;
    function ParseRecordType(const ATypeStr: string): TDNSRecordType; override;

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

uses
  Xml.XMLDoc,
  Xml.xmldom,
  Xml.adomxmldom;

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

function TRoute53DNSProvider.HmacSHA256(const AKey: TBytes; const AData: string): TBytes;
const
  BlockSize = 64; // SHA-256 block size
var
  Key: TBytes;
  DataBytes: TBytes;
  I: Integer;
  Ipad, Opad: TBytes;
  Inner: TBytes;
  InnerInput, OuterInput: TBytes;

  function Sha256Bytes(const Data: TBytes): TBytes;
  var
    Hasher: THashSHA2;
  begin
    Hasher := THashSHA2.Create(SHA256);
    Hasher.Update(Data);
    Result := Hasher.HashAsBytes;
  end;

begin
  DataBytes := TEncoding.UTF8.GetBytes(AData);

  Key := Copy(AKey);
  if Length(Key) > BlockSize then
    Key := Sha256Bytes(Key);

  SetLength(Key, BlockSize);

  SetLength(Ipad, BlockSize);
  SetLength(Opad, BlockSize);
  for I := 0 to BlockSize - 1 do
  begin
    Ipad[I] := Key[I] xor $36;
    Opad[I] := Key[I] xor $5c;
  end;

  // Inner = SHA256(i_key_pad || data)
  SetLength(InnerInput, Length(Ipad) + Length(DataBytes));
  if Length(Ipad) > 0 then
    Move(Ipad[0], InnerInput[0], Length(Ipad));
  if Length(DataBytes) > 0 then
    Move(DataBytes[0], InnerInput[Length(Ipad)], Length(DataBytes));
  Inner := Sha256Bytes(InnerInput);

  // Result = SHA256(o_key_pad || inner)
  SetLength(OuterInput, Length(Opad) + Length(Inner));
  if Length(Opad) > 0 then
    Move(Opad[0], OuterInput[0], Length(Opad));
  if Length(Inner) > 0 then
    Move(Inner[0], OuterInput[Length(Opad)], Length(Inner));
  Result := Sha256Bytes(OuterInput);
end;

function TRoute53DNSProvider.EnsureTrailingDot(const S: string): string;
begin
  Result := S;
  if (Result <> '') and not Result.EndsWith('.') then
    Result := Result + '.';
end;

function TRoute53DNSProvider.StripTrailingDot(const S: string): string;
begin
  Result := S;
  if Result.EndsWith('.') then
    Delete(Result, Length(Result), 1);
end;

function TRoute53DNSProvider.NormalizeRecordFqdn(const ARecordName, AZoneDomain: string): string;
var
  Name: string;
  Zone: string;
begin
  Zone := StripTrailingDot(AZoneDomain.Trim);
  Name := ARecordName.Trim;

  if (Name = '') or SameText(Name, '@') then
    Result := Zone
  else
  begin
    Name := StripTrailingDot(Name);
    if Name.EndsWith(Zone, True) then
      Result := Name
    else
      Result := Name + '.' + Zone;
  end;

  Result := EnsureTrailingDot(Result);
end;

function TRoute53DNSProvider.NormalizeRecordId(const ARecordName, AZoneDomain: string): string;
begin
  Result := StripTrailingDot(NormalizeRecordFqdn(ARecordName, AZoneDomain));
end;

function TRoute53DNSProvider.FindChildByLocalName(const AParent: IXMLNode; const ALocalName: string): IXMLNode;
var
  I: Integer;
  Child: IXMLNode;
begin
  Result := nil;
  if not Assigned(AParent) then
    Exit;

  for I := 0 to AParent.ChildNodes.Count - 1 do
  begin
    Child := AParent.ChildNodes[I];
    if SameText(Child.LocalName, ALocalName) then
      Exit(Child);
  end;
end;

function TRoute53DNSProvider.GetChildTextByLocalName(const AParent: IXMLNode; const ALocalName: string): string;
var
  Node: IXMLNode;
begin
  Node := FindChildByLocalName(AParent, ALocalName);
  if Assigned(Node) then
    Result := Node.Text
  else
    Result := '';
end;

function TRoute53DNSProvider.AwsUriEncode(const S: string): string;
var
  Bytes: TBytes;
  B: Byte;
  C: Char;
const
  Unreserved: set of AnsiChar = ['A'..'Z', 'a'..'z', '0'..'9', '-', '.', '_', '~'];
begin
  Result := '';
  Bytes := TEncoding.UTF8.GetBytes(S);
  for B in Bytes do
  begin
    C := Char(B);
    if AnsiChar(C) in Unreserved then
      Result := Result + C
    else
      Result := Result + '%' + IntToHex(B, 2);
  end;
end;

function TRoute53DNSProvider.CanonicalizeQueryString(const Query: string): string;
var
  Parts: TArray<string>;
  P: string;
  EqPos: Integer;
  NameRaw, ValueRaw: string;
  Items: TList<TPair<string,string>>;
  Pair: TPair<string,string>;
  I: Integer;
begin
  Result := '';
  if Query = '' then
    Exit;

  Items := TList<TPair<string,string>>.Create;
  try
    Parts := Query.Split(['&']);
    for P in Parts do
    begin
      if P = '' then
        Continue;

      EqPos := P.IndexOf('=');
      if EqPos < 0 then
      begin
        NameRaw := P;
        ValueRaw := '';
      end
      else
      begin
        NameRaw := P.Substring(0, EqPos);
        ValueRaw := P.Substring(EqPos + 1);
      end;

      Items.Add(TPair<string,string>.Create(AwsUriEncode(NameRaw), AwsUriEncode(ValueRaw)));
    end;

    // Sort by encoded name, then encoded value
    var J: Integer;
    var Tmp: TPair<string,string>;
    for I := 0 to Items.Count - 2 do
      for J := I + 1 to Items.Count - 1 do
      begin
        if (CompareText(Items[I].Key, Items[J].Key) > 0) or
           ((CompareText(Items[I].Key, Items[J].Key) = 0) and (CompareText(Items[I].Value, Items[J].Value) > 0)) then
        begin
          Tmp := Items[I];
          Items[I] := Items[J];
          Items[J] := Tmp;
        end;
      end;

    for I := 0 to Items.Count - 1 do
    begin
      Pair := Items[I];
      if I > 0 then
        Result := Result + '&';
      Result := Result + Pair.Key + '=' + Pair.Value;
    end;
  finally
    Items.Free;
  end;
end;

function TRoute53DNSProvider.ExecuteRequestXML(const AMethod: TRESTRequestMethod; const AResource: string; const ABody: string): IXMLDocument;
begin
  Result := nil;

  ConfigureRequest(AMethod, AResource);
 
  FRestRequest.Accept := 'application/xml';
  FRestRequest.AcceptCharset := 'utf-8';
  FRestClient.ContentType := 'application/xml';

  // Always clear prior body
  FRestRequest.ClearBody;
  if ABody <> '' then
    FRestRequest.AddBody(ABody, TRESTContentType.ctAPPLICATION_XML);

  SetAuthHeaders;

  FRestRequest.Execute;
  HandleRateLimiting;
  CheckResponse;

  if FRestResponse.Content <> '' then
  begin
    // Prefer a non-MSXML DOM vendor when available.
    var XmlDoc: TXMLDocument;
    XmlDoc := TXMLDocument.Create(nil);
    try
      XmlDoc.DOMVendor := GetDOMVendor('ADOM XML v4');
    except
      // Fallback to whatever is available on the machine
      XmlDoc.DOMVendor := GetDOMVendor(DefaultDOMVendor);
    end;
    XmlDoc.LoadFromXML(FRestResponse.Content);
    XmlDoc.Active := True;
    Result := XmlDoc;
  end;
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

procedure TRoute53DNSProvider.SignRequest(
  const AMethod: TRESTRequestMethod;
  const AResource: string
);
var
  AmzDate, DateStamp: string;
  Payload, PayloadHash: string;
  Host, UriPath, RawQuery, CanonicalQuery: string;
  CanonicalHeaders, SignedHeaders, CredentialScope: string;
  CanonicalRequest, HashedCanonicalRequest: string;
  StringToSign, Signature, AuthHeader: string;
  NowDT: TDateTime;
  HashBytes: TBytes;
begin
  // ---- Time (UTC) ----
  NowDT := NowUTC;
  AmzDate := ISO8601DateTime(NowDT); // YYYYMMDDTHHMMSSZ
  DateStamp := ISO8601Date(NowDT);   // YYYYMMDD

  // ---- Payload hash (UTF-8 string) ----
  Payload := TCustomRESTRequest(FRestRequest).GetFullRequestBody;

  if Payload = '' then
  begin
    // SHA256 of empty string (required by SigV4)
    PayloadHash :=
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  end
  else
  begin
    var Hasher: THashSHA2;
    Hasher := THashSHA2.Create(SHA256);
    Hasher.Update(TEncoding.UTF8.GetBytes(Payload));
    HashBytes := Hasher.HashAsBytes;
    PayloadHash := BytesToHexString(HashBytes);
  end;

  // ---- URI ----
  // Important: `TRESTRequest.Resource` may be normalized (no leading '/'),
  // so always enforce a leading slash when building the canonical URI.
  var ResourceWithLeadingSlash := '/' + AResource.TrimLeft(['/']);
  var QPos := Pos('?', ResourceWithLeadingSlash);
  if QPos > 0 then
  begin
    UriPath := Copy(ResourceWithLeadingSlash, 1, QPos - 1);
    RawQuery := Copy(ResourceWithLeadingSlash, QPos + 1, MaxInt);
  end
  else
  begin
    UriPath := ResourceWithLeadingSlash;
    RawQuery := '';
  end;

  CanonicalQuery := CanonicalizeQueryString(RawQuery);
  Host := TURI.Create(FRestClient.BaseURL).Host;

  // ---- Canonical headers (MUST match SignedHeaders) ----
  CanonicalHeaders :=
    'host:' + Host + #10 +
    'x-amz-content-sha256:' + PayloadHash + #10 +
    'x-amz-date:' + AmzDate + #10;

  SignedHeaders := 'host;x-amz-content-sha256;x-amz-date';

  // ---- Credential scope (Route53 is ALWAYS us-east-1) ----
  CredentialScope :=
    DateStamp + '/us-east-1/route53/aws4_request';

  // ---- Canonical request ----
  CanonicalRequest :=
    RESTRequestMethodToString(AMethod) + #10 +
    UriPath + #10 +
    CanonicalQuery + #10 +
    CanonicalHeaders + #10 +
    SignedHeaders + #10 +
    PayloadHash;

  var CanonHasher: THashSHA2;
  CanonHasher := THashSHA2.Create(SHA256);
  CanonHasher.Update(TEncoding.UTF8.GetBytes(CanonicalRequest));
  HashBytes := CanonHasher.HashAsBytes;
  HashedCanonicalRequest := BytesToHexString(HashBytes);

  // ---- String to sign ----
  StringToSign :=
    'AWS4-HMAC-SHA256' + #10 +
    AmzDate + #10 +
    CredentialScope + #10 +
    HashedCanonicalRequest;

  // ---- Signature ----
  Signature :=
    CalculateSignature(
      FAwsSecretKey,
      DateStamp,
      'us-east-1',
      'route53',
      StringToSign
    );

  // ---- Authorization header ----
  AuthHeader :=
    'AWS4-HMAC-SHA256 Credential=' + FAwsAccessKey + '/' + CredentialScope +
    ', SignedHeaders=' + SignedHeaders +
    ', Signature=' + Signature;

  // ---- Apply headers ----
  // Keep existing params (e.g., Content-Type from AddBody), only replace auth headers.
  FRestRequest.Params.Delete('Authorization');
  FRestRequest.Params.Delete('x-amz-date');
  FRestRequest.Params.Delete('x-amz-content-sha256');

  // Do NOT set the Host header manually: if it is wrong, the request URL becomes invalid
  // and AWS will reject the signature. The HTTP stack will send the correct host.

  FRestRequest.AddParameter(
    'x-amz-content-sha256',
    PayloadHash,
    pkHTTPHEADER,
    [poDoNotEncode]
  );
  FRestRequest.AddParameter(
    'Authorization',
    AuthHeader,
    pkHTTPHEADER,
    [poDoNotEncode]
  );
  FRestRequest.AddParameter(
    'x-amz-date',
    AmzDate,
    pkHTTPHEADER,
    [poDoNotEncode]
  );
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

constructor TRoute53DNSProvider.Create(const AAwsAccessKey, AAwsSecretKey: string; const ARegion: string);
begin
  inherited Create('', '');
  FAwsAccessKey := AAwsAccessKey;
  FAwsSecretKey := AAwsSecretKey;
  FRegion := ARegion;
  FRestClient.BaseURL := 'https://route53.amazonaws.com';
  FRestRequest.Accept := 'application/xml';
  FRestClient.ContentType := 'application/xml';
end;

function TRoute53DNSProvider.ListZones: TObjectList<TDNSZone>;
var
  Doc: IXMLDocument;
  Root: IXMLNode;
  HostedZonesNode: IXMLNode;
  ZoneNode: IXMLNode;
  I: Integer;
  Zone: TDNSZone;
  IdText: string;
  NameText: string;
  SlashPos: Integer;
  Marker: string;
  IsTruncated: string;
  NextMarker: string;
  Resource: string;
begin
  Result := TObjectList<TDNSZone>.Create(True);

  Marker := '';
  repeat
    Resource := '/2013-04-01/hostedzone';
    if Marker <> '' then
      Resource := Resource + '?marker=' + Marker;

    Doc := ExecuteRequestXML(rmGET, Resource);
    if not Assigned(Doc) then
      Exit;

    Root := Doc.DocumentElement;

    HostedZonesNode := FindChildByLocalName(Root, 'HostedZones');
    if Assigned(HostedZonesNode) then
    begin
      for I := 0 to HostedZonesNode.ChildNodes.Count - 1 do
      begin
        ZoneNode := HostedZonesNode.ChildNodes[I];
        if not SameText(ZoneNode.LocalName, 'HostedZone') then
          Continue;

        IdText := GetChildTextByLocalName(ZoneNode, 'Id');
        NameText := GetChildTextByLocalName(ZoneNode, 'Name');

        Zone := TDNSZone.Create;
        try
          SlashPos := LastDelimiter('/', IdText);
          if SlashPos > 0 then
            Zone.Id := Copy(IdText, SlashPos + 1, MaxInt)
          else
            Zone.Id := IdText;

          Zone.Domain := StripTrailingDot(NameText);
          Result.Add(Zone);
        except
          FreeAndNil(Zone);
          raise;
        end;
      end;
    end;

    IsTruncated := GetChildTextByLocalName(Root, 'IsTruncated');
    NextMarker := GetChildTextByLocalName(Root, 'NextMarker');

    if SameText(IsTruncated, 'true') and (NextMarker <> '') then
      Marker := NextMarker
    else
      Marker := '';

  until Marker = '';
end;

function TRoute53DNSProvider.GetZone(const ADomain: string): TDNSZone;
var
  Zones: TObjectList<TDNSZone>;
  Z: TDNSZone;
begin
  Zones := ListZones;
  try
    for Z in Zones do
      if SameText(Z.Domain, ADomain) then
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
const
  XmlNs = 'https://route53.amazonaws.com/doc/2013-04-01/';
var
  Body: string;
  Doc: IXMLDocument;
  Root: IXMLNode;
  HostedZoneNode: IXMLNode;
  IdText: string;
  NameText: string;
  SlashPos: Integer;
begin
  Body :=
    '<CreateHostedZoneRequest xmlns="' + XmlNs + '">' +
      '<Name>' + EnsureTrailingDot(StripTrailingDot(ADomain)) + '</Name>' +
      '<CallerReference>' + TGuid.NewGuid.ToString + '</CallerReference>' +
    '</CreateHostedZoneRequest>';

  Doc := ExecuteRequestXML(rmPOST, '/2013-04-01/hostedzone', Body);
  Root := Doc.DocumentElement;
  HostedZoneNode := FindChildByLocalName(Root, 'HostedZone');
  if not Assigned(HostedZoneNode) then
    raise EDNSAPIException.Create('Route53 response missing HostedZone');

  IdText := GetChildTextByLocalName(HostedZoneNode, 'Id');
  NameText := GetChildTextByLocalName(HostedZoneNode, 'Name');

  Result := TDNSZone.Create;
  try
    SlashPos := LastDelimiter('/', IdText);
    if SlashPos > 0 then
      Result.Id := Copy(IdText, SlashPos + 1, MaxInt)
    else
      Result.Id := IdText;

    Result.Domain := StripTrailingDot(NameText);
  except
    FreeAndNil(Result);
    raise;
  end;
end;

function TRoute53DNSProvider.DeleteZone(const ADomain: string): Boolean;
var
  Zone: TDNSZone;
begin
  Zone := GetZone(ADomain);
  try
    ExecuteRequestXML(rmDELETE, '/2013-04-01/hostedzone/' + Zone.Id);
    Result := True;
  finally
    FreeAndNil(Zone);
  end;
end;

function TRoute53DNSProvider.ListRecords(const ADomain: string; ARecordType: TDNSRecordType): TObjectList<TDNSRecord>;
var
  Zone: TDNSZone;
  Doc: IXMLDocument;
  Root: IXMLNode;
  SetsNode: IXMLNode;
  SetNode: IXMLNode;
  I: Integer;
  Rec: TDNSRecord;
  NameText: string;
  TypeText: string;
  TtlText: string;
  RecordsNode: IXMLNode;
  RecordNode: IXMLNode;
  ValueText: string;
  ValueParts: TArray<string>;
begin
  Result := TObjectList<TDNSRecord>.Create(True);

  Zone := GetZone(ADomain);
  try
    Doc := ExecuteRequestXML(rmGET, '/2013-04-01/hostedzone/' + Zone.Id + '/rrset');
    Root := Doc.DocumentElement;
    SetsNode := FindChildByLocalName(Root, 'ResourceRecordSets');
    if not Assigned(SetsNode) then
      Exit;

    for I := 0 to SetsNode.ChildNodes.Count - 1 do
    begin
      SetNode := SetsNode.ChildNodes[I];
      if not SameText(SetNode.LocalName, 'ResourceRecordSet') then
        Continue;

      NameText := StripTrailingDot(GetChildTextByLocalName(SetNode, 'Name'));
      TypeText := GetChildTextByLocalName(SetNode, 'Type');
      TtlText := GetChildTextByLocalName(SetNode, 'TTL');

      Rec := TDNSRecord.Create;
      try
        Rec.Name := NameText;
        Rec.RecordType := ParseRecordType(TypeText);
        Rec.TTL := StrToIntDef(TtlText, 300);

        RecordsNode := FindChildByLocalName(SetNode, 'ResourceRecords');
        if Assigned(RecordsNode) then
        begin
          RecordNode := FindChildByLocalName(RecordsNode, 'ResourceRecord');
          if Assigned(RecordNode) then
          begin
            ValueText := GetChildTextByLocalName(RecordNode, 'Value');

            // Parse MX priority if present
            if Rec.RecordType = drtMX then
            begin
              ValueParts := ValueText.Split([' '], 2);
              if Length(ValueParts) = 2 then
              begin
                Rec.Priority := StrToIntDef(ValueParts[0], 0);
                Rec.Value := ValueParts[1];
              end
              else
                Rec.Value := ValueText;
            end
            else
              Rec.Value := ValueText;
          end;
        end;

        // Filter
        if (ARecordType = drtA) or (Rec.RecordType = ARecordType) then
          Result.Add(Rec)
        else
          FreeAndNil(Rec);
      except
        FreeAndNil(Rec);
        raise;
      end;
    end;
  finally
    FreeAndNil(Zone);
  end;
end;

function TRoute53DNSProvider.CreateRecord(const ADomain: string; ARecord: TDNSRecord): TDNSRecord;
const
  XmlNs = 'https://route53.amazonaws.com/doc/2013-04-01/';
var
  Zone: TDNSZone;
  Body: string;
  RecordName: string;
  RecordValue: string;
begin
  if not ValidateRecord(ARecord) then
    raise EDNSException.Create('Invalid record');

  Zone := GetZone(ADomain);
  try
    RecordName := NormalizeRecordFqdn(ARecord.Name, ADomain);

    RecordValue := ARecord.Value;
    if ARecord.RecordType = drtMX then
      RecordValue := IntToStr(ARecord.Priority) + ' ' + RecordValue;
    if ARecord.RecordType = drtTXT then
    begin
      if (RecordValue <> '') and not (RecordValue.StartsWith('"') and RecordValue.EndsWith('"')) then
        RecordValue := '"' + RecordValue + '"';
    end;

    Body :=
      '<ChangeResourceRecordSetsRequest xmlns="' + XmlNs + '">' +
        '<ChangeBatch>' +
          '<Changes>' +
            '<Change>' +
              '<Action>UPSERT</Action>' +
              '<ResourceRecordSet>' +
                '<Name>' + RecordName + '</Name>' +
                '<Type>' + GetRecordTypeString(ARecord.RecordType) + '</Type>' +
                '<TTL>' + IntToStr(ARecord.TTL) + '</TTL>' +
                '<ResourceRecords>' +
                  '<ResourceRecord><Value>' + RecordValue + '</Value></ResourceRecord>' +
                '</ResourceRecords>' +
              '</ResourceRecordSet>' +
            '</Change>' +
          '</Changes>' +
        '</ChangeBatch>' +
      '</ChangeResourceRecordSetsRequest>';

    ExecuteRequestXML(rmPOST, '/2013-04-01/hostedzone/' + Zone.Id + '/rrset', Body);

    Result := ARecord.Clone;
    Result.Id := NormalizeRecordId(ARecord.Name, ADomain);
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
const
  XmlNs = 'https://route53.amazonaws.com/doc/2013-04-01/';
var
  Rec: TDNSRecord;
  Zone: TDNSZone;
  Body: string;
  RecordName: string;
  RecordValue: string;
begin
  Rec := GetRecord(ADomain, ARecordId);
  try
    Zone := GetZone(ADomain);
    try
      RecordName := EnsureTrailingDot(Rec.Name);

      RecordValue := Rec.Value;
      if Rec.RecordType = drtMX then
        RecordValue := IntToStr(Rec.Priority) + ' ' + RecordValue;
      if Rec.RecordType = drtTXT then
      begin
        if (RecordValue <> '') and not (RecordValue.StartsWith('"') and RecordValue.EndsWith('"')) then
          RecordValue := '"' + RecordValue + '"';
      end;

      Body :=
        '<ChangeResourceRecordSetsRequest xmlns="' + XmlNs + '">' +
          '<ChangeBatch>' +
            '<Changes>' +
              '<Change>' +
                '<Action>DELETE</Action>' +
                '<ResourceRecordSet>' +
                  '<Name>' + RecordName + '</Name>' +
                  '<Type>' + GetRecordTypeString(Rec.RecordType) + '</Type>' +
                  '<TTL>' + IntToStr(Rec.TTL) + '</TTL>' +
                  '<ResourceRecords>' +
                    '<ResourceRecord><Value>' + RecordValue + '</Value></ResourceRecord>' +
                  '</ResourceRecords>' +
                '</ResourceRecordSet>' +
              '</Change>' +
            '</Changes>' +
          '</ChangeBatch>' +
        '</ChangeResourceRecordSetsRequest>';

      ExecuteRequestXML(rmPOST, '/2013-04-01/hostedzone/' + Zone.Id + '/rrset', Body);
      Result := True;
    finally
     FreeAndNil(Zone);
    end;
  finally
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
