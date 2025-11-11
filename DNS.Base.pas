unit DNS.Base;

interface

uses
  System.SysUtils,
  System.Classes,
  System.Generics.Collections,
  System.JSON,
  REST.Client,
  REST.Types,
  REST.Authenticator.Basic,
  IPPeerClient,
  REST.Response.Adapter;

type
  // DNS record types enum
  TDNSRecordType = (
    drtA,         // IPv4 address
    drtAAAA,      // IPv6 address
    drtCNAME,     // Canonical name
    drtMX,        // Mail exchange
    drtTXT,       // Text record
    drtNS,        // Name server
    drtSOA,       // Start of authority
    drtSRV,       // Service record
    drtPTR,       // Pointer record
    drtCAA        // Certification Authority Authorization
  );

  // DNS record data structure
  TDNSRecord = class
  private
    FId: string;
    FName: string;
    FRecordType: TDNSRecordType;
    FValue: string;
    FTTL: Integer;
    FPriority: Integer;  // For MX and SRV records
    FWeight: Integer;     // For SRV records
    FPort: Integer;       // For SRV records
    FFlags: Integer;      // For CAA records
    FTag: string;         // For CAA records
  public
    constructor Create;

    property Id: string read FId write FId;
    property Name: string read FName write FName;
    property RecordType: TDNSRecordType read FRecordType write FRecordType;
    property Value: string read FValue write FValue;
    property TTL: Integer read FTTL write FTTL;
    property Priority: Integer read FPriority write FPriority;
    property Weight: Integer read FWeight write FWeight;
    property Port: Integer read FPort write FPort;
    property Flags: Integer read FFlags write FFlags;
    property Tag: string read FTag write FTag;

    function Clone: TDNSRecord;
    function ToJSON: TJSONObject; virtual;
    procedure FromJSON(AJson: TJSONObject); virtual;
  end;

  // DNS Zone/Domain information
  TDNSZone = class
  private
    FId: string;
    FDomain: string;
    FCreatedAt: TDateTime;
    FUpdatedAt: TDateTime;
    FNameServers: TStringList;
  public
    constructor Create;
    destructor Destroy; override;

    property Id: string read FId write FId;
    property Domain: string read FDomain write FDomain;
    property CreatedAt: TDateTime read FCreatedAt write FCreatedAt;
    property UpdatedAt: TDateTime read FUpdatedAt write FUpdatedAt;
    property NameServers: TStringList read FNameServers;
  end;

  // Base exception for DNS operations
  EDNSException = class(Exception);
  EDNSAuthException = class(EDNSException);
  EDNSRecordNotFound = class(EDNSException);
  EDNSZoneNotFound = class(EDNSException);
  EDNSAPIException = class(EDNSException);

  // Forward declaration
  TBaseDNSProvider = class;

  // Event types for async operations
  TDNSOperationEvent = procedure(Sender: TObject; const Success: Boolean;
    const ErrorMessage: string) of object;
  TDNSRecordsEvent = procedure(Sender: TObject; const Records: TObjectList<TDNSRecord>) of object;

  // Base DNS Provider class
  TBaseDNSProvider = class abstract
  protected
    FApiKey: string;
    FApiSecret: string;
    FBaseUrl: string;
    FRestClient: TRESTClient;
    FRestRequest: TRESTRequest;
    FRestResponse: TRESTResponse;
    FTimeout: Integer;
    FLastError: string;
    FRateLimitRemaining: Integer;
    FRateLimitReset: TDateTime;
  protected
    function GetRecordTypeString(AType: TDNSRecordType): string; virtual;
    function ParseRecordType(const ATypeStr: string): TDNSRecordType; virtual;

    // REST helper methods
    function ExecuteRequest(const AMethod: TRESTRequestMethod;
      const AResource: string; APayload: TJSONObject = nil): TJSONValue; virtual;
    procedure ConfigureRequest(const AMethod: TRESTRequestMethod;
      const AResource: string); virtual;
    procedure SetAuthHeaders; virtual; abstract;
    procedure HandleRateLimiting; virtual;
    procedure CheckResponse; virtual;

    // Provider-specific JSON parsing
    function ParseRecord(AJson: TJSONObject): TDNSRecord; virtual; abstract;
    function RecordToJSON(ARecord: TDNSRecord): TJSONObject; virtual; abstract;
    function ParseZone(AJson: TJSONObject): TDNSZone; virtual; abstract;
  public
    constructor Create(const AApiKey: string; const AApiSecret: string = ''); virtual;
    destructor Destroy; override;

    // Zone/Domain operations
    function ListZones: TObjectList<TDNSZone>; virtual; abstract;
    function GetZone(const ADomain: string): TDNSZone; virtual; abstract;
    function CreateZone(const ADomain: string): TDNSZone; virtual; abstract;
    function DeleteZone(const ADomain: string): Boolean; virtual; abstract;

    // DNS Record operations
    function ListRecords(const ADomain: string;
      ARecordType: TDNSRecordType = drtA): TObjectList<TDNSRecord>; virtual; abstract;
    function GetRecord(const ADomain, ARecordId: string): TDNSRecord; virtual; abstract;
    function CreateRecord(const ADomain: string; ARecord: TDNSRecord): TDNSRecord; virtual; abstract;
    function UpdateRecord(const ADomain: string; ARecord: TDNSRecord): Boolean; virtual; abstract;
    function DeleteRecord(const ADomain, ARecordId: string): Boolean; virtual; abstract;

    // Bulk operations (optional implementation)
    function CreateRecordsBulk(const ADomain: string;
      ARecords: TObjectList<TDNSRecord>): Boolean; virtual;
    function DeleteRecordsBulk(const ADomain: string;
      ARecordIds: TArray<string>): Boolean; virtual;

    // Validation methods
    function ValidateRecord(ARecord: TDNSRecord): Boolean; virtual;
    function ValidateDomain(const ADomain: string): Boolean; virtual;

    // Provider capabilities
    function SupportsRecordType(AType: TDNSRecordType): Boolean; virtual;
    function GetMaxTTL: Integer; virtual;
    function GetMinTTL: Integer; virtual;

    property ApiKey: string read FApiKey write FApiKey;
    property ApiSecret: string read FApiSecret write FApiSecret;
    property BaseUrl: string read FBaseUrl write FBaseUrl;
    property Timeout: Integer read FTimeout write FTimeout;
    property LastError: string read FLastError;
    property RateLimitRemaining: Integer read FRateLimitRemaining;
    property RateLimitReset: TDateTime read FRateLimitReset;
  end;

  // Helper class for DNS record validation
  TDNSValidator = class
  public
    class function IsValidIPv4(const AValue: string): Boolean;
    class function IsValidIPv6(const AValue: string): Boolean;
    class function IsValidDomain(const ADomain: string): Boolean;
    class function IsValidHostname(const AHostname: string): Boolean;
    class function ValidateRecordValue(ARecord: TDNSRecord): Boolean;
  end;

implementation

uses
  System.RegularExpressions,
  System.DateUtils,
  System.TypInfo;

{ TDNSRecord }

constructor TDNSRecord.Create;
begin
  inherited;
  FTTL := 3600; // Default 1 hour
  FPriority := 10; // Default priority for MX
end;

function TDNSRecord.Clone: TDNSRecord;
begin
  Result := TDNSRecord.Create;
  Result.FId := FId;
  Result.FName := FName;
  Result.FRecordType := FRecordType;
  Result.FValue := FValue;
  Result.FTTL := FTTL;
  Result.FPriority := FPriority;
  Result.FWeight := FWeight;
  Result.FPort := FPort;
  Result.FFlags := FFlags;
  Result.FTag := FTag;
end;

function TDNSRecord.ToJSON: TJSONObject;
begin
  Result := TJSONObject.Create;
  try
    Result.AddPair('id', FId);
    Result.AddPair('name', FName);
    Result.AddPair('type', GetEnumName(TypeInfo(TDNSRecordType), Ord(FRecordType)));
    Result.AddPair('value', FValue);
    Result.AddPair('ttl', TJSONNumber.Create(FTTL));

    if FRecordType in [drtMX, drtSRV] then
      Result.AddPair('priority', TJSONNumber.Create(FPriority));

    if FRecordType = drtSRV then
    begin
      Result.AddPair('weight', TJSONNumber.Create(FWeight));
      Result.AddPair('port', TJSONNumber.Create(FPort));
    end;

    if FRecordType = drtCAA then
    begin
      Result.AddPair('flags', TJSONNumber.Create(FFlags));
      Result.AddPair('tag', FTag);
    end;
  except
    Result.Free;
    raise;
  end;
end;

procedure TDNSRecord.FromJSON(AJson: TJSONObject);
var
  LTypeStr: string;
begin
  if AJson.TryGetValue<string>('id', FId) then ;
  if AJson.TryGetValue<string>('name', FName) then ;
  if AJson.TryGetValue<string>('value', FValue) then ;
  if AJson.TryGetValue<Integer>('ttl', FTTL) then ;
  if AJson.TryGetValue<Integer>('priority', FPriority) then ;
  if AJson.TryGetValue<Integer>('weight', FWeight) then ;
  if AJson.TryGetValue<Integer>('port', FPort) then ;
  if AJson.TryGetValue<Integer>('flags', FFlags) then ;
  if AJson.TryGetValue<string>('tag', FTag) then ;

  if AJson.TryGetValue<string>('type', LTypeStr) then
  begin
    // Parse type string to enum - provider specific implementation may override
  end;
end;

{ TDNSZone }

constructor TDNSZone.Create;
begin
  inherited;
  FNameServers := TStringList.Create;
end;

destructor TDNSZone.Destroy;
begin
  FNameServers.Free;
  inherited;
end;

{ TBaseDNSProvider }

constructor TBaseDNSProvider.Create(const AApiKey: string; const AApiSecret: string);
begin
  inherited Create;
  FApiKey := AApiKey;
  FApiSecret := AApiSecret;

  // Create REST components
  FRestClient := TRESTClient.Create(nil);
  FRestResponse := TRESTResponse.Create(nil);
  FRestRequest := TRESTRequest.Create(nil);

  // Configure REST components
  FRestRequest.Client := FRestClient;
  FRestRequest.Response := FRestResponse;
  FRestRequest.Accept := 'application/json';

  // Set default timeout
  FTimeout := 30000;
  FRestClient.ConnectTimeout := FTimeout;
  FRestClient.ReadTimeout := FTimeout;
end;

destructor TBaseDNSProvider.Destroy;
begin
  FRestRequest.Free;
  FRestResponse.Free;
  FRestClient.Free;
  inherited;
end;

procedure TBaseDNSProvider.ConfigureRequest(const AMethod: TRESTRequestMethod;
  const AResource: string);
begin
  FRestRequest.Method := AMethod;
  FRestRequest.Resource := AResource;
  FRestRequest.Params.Clear;

  // Set authentication headers
  SetAuthHeaders;
end;

function TBaseDNSProvider.ExecuteRequest(const AMethod: TRESTRequestMethod;
  const AResource: string; APayload: TJSONObject): TJSONValue;
begin
  Result := nil;
  FLastError := '';

  try
    // Configure the request
    ConfigureRequest(AMethod, AResource);

    // Add payload if present
    if Assigned(APayload) then
    begin
      FRestRequest.ClearBody;
      FRestRequest.AddBody(APayload.ToJSON, TRESTContentType.ctAPPLICATION_JSON);
    end;

    // Execute the request
    FRestRequest.Execute;

    // Handle rate limiting
    HandleRateLimiting;

    // Check response status
    CheckResponse;

    // Parse JSON response if present
    if (FRestResponse.Content <> '') and
       (FRestResponse.StatusCode <> 204) then  // 204 No Content
    begin
      Result := TJSONObject.ParseJSONValue(FRestResponse.Content);
    end;
  except
    on E: Exception do
    begin
      FLastError := E.Message;
      raise;
    end;
  end;
end;

procedure TBaseDNSProvider.CheckResponse;
begin
  if FRestResponse.StatusCode >= 400 then
  begin
    FLastError := Format('HTTP %d: %s',
      [FRestResponse.StatusCode, FRestResponse.StatusText]);

    if FRestResponse.Content <> '' then
      FLastError := FLastError + ' - ' + FRestResponse.Content;

    case FRestResponse.StatusCode of
      401, 403: raise EDNSAuthException.Create(FLastError);
      404: raise EDNSRecordNotFound.Create(FLastError);
    else
      raise EDNSAPIException.Create(FLastError);
    end;
  end;
end;

procedure TBaseDNSProvider.HandleRateLimiting;
var
  LRemaining, LReset: string;
begin
  // Check for rate limiting headers (common patterns)
  LRemaining := FRestResponse.Headers.Values['X-RateLimit-Remaining'];
  if LRemaining = '' then
    LRemaining := FRestResponse.Headers.Values['X-Ratelimit-Remaining'];

  LReset := FRestResponse.Headers.Values['X-RateLimit-Reset'];
  if LReset = '' then
    LReset := FRestResponse.Headers.Values['X-Ratelimit-Reset'];

  if LRemaining <> '' then
    FRateLimitRemaining := StrToIntDef(LRemaining, -1);

  if LReset <> '' then
    FRateLimitReset := UnixToDateTime(StrToInt64Def(LReset, 0));
end;

function TBaseDNSProvider.GetRecordTypeString(AType: TDNSRecordType): string;
const
  RecordTypeStrings: array[TDNSRecordType] of string = (
    'A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'PTR', 'CAA'
  );
begin
  Result := RecordTypeStrings[AType];
end;

function TBaseDNSProvider.ParseRecordType(const ATypeStr: string): TDNSRecordType;
begin
  if SameText(ATypeStr, 'A') then Result := drtA
  else if SameText(ATypeStr, 'AAAA') then Result := drtAAAA
  else if SameText(ATypeStr, 'CNAME') then Result := drtCNAME
  else if SameText(ATypeStr, 'MX') then Result := drtMX
  else if SameText(ATypeStr, 'TXT') then Result := drtTXT
  else if SameText(ATypeStr, 'NS') then Result := drtNS
  else if SameText(ATypeStr, 'SOA') then Result := drtSOA
  else if SameText(ATypeStr, 'SRV') then Result := drtSRV
  else if SameText(ATypeStr, 'PTR') then Result := drtPTR
  else if SameText(ATypeStr, 'CAA') then Result := drtCAA
  else Result := drtA; // Default
end;

function TBaseDNSProvider.CreateRecordsBulk(const ADomain: string;
  ARecords: TObjectList<TDNSRecord>): Boolean;
var
  LRecord: TDNSRecord;
begin
  // Default implementation: create records one by one
  Result := True;
  for LRecord in ARecords do
  begin
    try
      CreateRecord(ADomain, LRecord);
    except
      Result := False;
      raise;
    end;
  end;
end;

function TBaseDNSProvider.DeleteRecordsBulk(const ADomain: string;
  ARecordIds: TArray<string>): Boolean;
var
  LId: string;
begin
  // Default implementation: delete records one by one
  Result := True;
  for LId in ARecordIds do
  begin
    try
      DeleteRecord(ADomain, LId);
    except
      Result := False;
      raise;
    end;
  end;
end;

function TBaseDNSProvider.ValidateRecord(ARecord: TDNSRecord): Boolean;
begin
  Result := TDNSValidator.ValidateRecordValue(ARecord);
end;

function TBaseDNSProvider.ValidateDomain(const ADomain: string): Boolean;
begin
  Result := TDNSValidator.IsValidDomain(ADomain);
end;

function TBaseDNSProvider.SupportsRecordType(AType: TDNSRecordType): Boolean;
begin
  // Default: support common types
  Result := AType in [drtA, drtAAAA, drtCNAME, drtMX, drtTXT, drtNS];
end;

function TBaseDNSProvider.GetMaxTTL: Integer;
begin
  Result := 86400; // 24 hours default
end;

function TBaseDNSProvider.GetMinTTL: Integer;
begin
  Result := 60; // 1 minute default
end;

{ TDNSValidator }

class function TDNSValidator.IsValidIPv4(const AValue: string): Boolean;
var
  LRegex: TRegEx;
  Parts: TArray<string>;
  Part: string;
begin
  LRegex := TRegEx.Create('^(\d{1,3}\.){3}\d{1,3}$');
  Result := LRegex.IsMatch(AValue);
  if Result then
  begin
    // Additional validation for each octet
    Parts := AValue.Split(['.']);
    for Part in Parts do
      if StrToIntDef(Part, -1) > 255 then
        Exit(False);
  end;
end;

class function TDNSValidator.IsValidIPv6(const AValue: string): Boolean;
var
  LRegex: TRegEx;
begin
  // Simplified IPv6 validation
  LRegex := TRegEx.Create('^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$');
  Result := LRegex.IsMatch(AValue);
end;

class function TDNSValidator.IsValidDomain(const ADomain: string): Boolean;
var
  LRegex: TRegEx;
begin
  LRegex := TRegEx.Create('^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$');
  Result := LRegex.IsMatch(ADomain);
end;

class function TDNSValidator.IsValidHostname(const AHostname: string): Boolean;
var
  LRegex: TRegEx;
begin
  if AHostname = '@' then // Root domain
    Exit(True);

  LRegex := TRegEx.Create('^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$');
  Result := LRegex.IsMatch(AHostname);
end;

class function TDNSValidator.ValidateRecordValue(ARecord: TDNSRecord): Boolean;
begin
  Result := False;

  case ARecord.RecordType of
    drtA: Result := IsValidIPv4(ARecord.Value);
    drtAAAA: Result := IsValidIPv6(ARecord.Value);
    drtCNAME, drtNS: Result := IsValidDomain(ARecord.Value);
    drtMX: Result := IsValidDomain(ARecord.Value) and (ARecord.Priority > 0);
    drtTXT: Result := Length(ARecord.Value) <= 255; // Most providers limit TXT records
    drtSRV: Result := IsValidDomain(ARecord.Value) and
                      (ARecord.Priority >= 0) and
                      (ARecord.Weight >= 0) and
                      (ARecord.Port > 0) and (ARecord.Port < 65536);
    drtPTR: Result := IsValidDomain(ARecord.Value);
    drtCAA: Result := (ARecord.Flags >= 0) and (ARecord.Flags <= 255) and
                      (ARecord.Tag <> '') and (ARecord.Value <> '');
    else
      Result := True; // Allow other types by default
  end;
end;

end.
