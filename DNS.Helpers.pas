unit DNS.Helpers;

interface


uses
  System.SysUtils,
  System.TypInfo,
  DNS.Base;

type
  TDNSRecordTypeHelper = record helper for TDNSRecordType
  public
    // Convert to string representations
    function ToString: string;
    function ToShortString: string;
    function ToLongString: string;
    function ToDescription: string;

    // Parse from string
    class function FromString(const AValue: string): TDNSRecordType; static;
    class function TryFromString(const AValue: string; out AType: TDNSRecordType): Boolean; static;

    // Validation helpers
    function RequiresPriority: Boolean;
    function RequiresPort: Boolean;
    function RequiresWeight: Boolean;
    function RequiresFlags: Boolean;
    function RequiresTag: Boolean;
    function IsIPRecord: Boolean;
    function IsNameRecord: Boolean;
    function IsTextRecord: Boolean;

    // Common operations
    function GetDefaultTTL: Integer;
    function GetMaxValueLength: Integer;
    function GetDefaultPriority: Integer;
    function ValidateValue(const AValue: string): Boolean;
    function GetExampleValue: string;
    function GetRecordIcon: string;  // Returns Unicode emoji/symbol for UI

    // RFC and specification info
    function GetRFCNumber: string;
    function GetStandardPort: Integer;  // For SRV records
    function IsDeprecated: Boolean;
    function IsExperimental: Boolean;

    // Provider support helpers
    function IsCommonlySupported: Boolean;
    function GetMinTTL: Integer;
    function GetMaxTTL: Integer;
  end;

  // Additional helper for arrays of DNS record types
  TDNSRecordTypeArrayHelper = record helper for TArray<TDNSRecordType>
  public
    function Contains(AType: TDNSRecordType): Boolean;
    function ToString: string;
    procedure Add(AType: TDNSRecordType);
    procedure Remove(AType: TDNSRecordType);
  end;

implementation

uses
  System.RegularExpressions;

{ TDNSRecordTypeHelper }

function TDNSRecordTypeHelper.ToString: string;
const
  RecordTypeStrings: array[TDNSRecordType] of string = (
    'A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'PTR', 'CAA'
  );
begin
  Result := RecordTypeStrings[Self];
end;

function TDNSRecordTypeHelper.ToShortString: string;
begin
  Result := ToString;  // Short string is the same as ToString
end;

function TDNSRecordTypeHelper.ToLongString: string;
const
  LongNames: array[TDNSRecordType] of string = (
    'A (IPv4 Address)',
    'AAAA (IPv6 Address)',
    'CNAME (Canonical Name)',
    'MX (Mail Exchange)',
    'TXT (Text)',
    'NS (Name Server)',
    'SOA (Start of Authority)',
    'SRV (Service)',
    'PTR (Pointer)',
    'CAA (Certification Authority Authorization)'
  );
begin
  Result := LongNames[Self];
end;

function TDNSRecordTypeHelper.ToDescription: string;
const
  Descriptions: array[TDNSRecordType] of string = (
    'Maps a domain name to an IPv4 address',
    'Maps a domain name to an IPv6 address',
    'Creates an alias from one domain name to another',
    'Specifies mail servers for the domain',
    'Holds arbitrary text data',
    'Delegates a domain to a set of name servers',
    'Specifies authoritative information about a DNS zone',
    'Defines the location of services',
    'Maps an IP address to a domain name (reverse DNS)',
    'Specifies which certificate authorities can issue certificates for the domain'
  );
begin
  Result := Descriptions[Self];
end;

class function TDNSRecordTypeHelper.FromString(const AValue: string): TDNSRecordType;
begin
  if not TryFromString(AValue, Result) then
    raise Exception.CreateFmt('Invalid DNS record type: %s', [AValue]);
end;

class function TDNSRecordTypeHelper.TryFromString(const AValue: string;
  out AType: TDNSRecordType): Boolean;
var
  LValue: string;
begin
  Result := True;
  LValue := UpperCase(Trim(AValue));

  if (LValue = 'A') or (LValue = 'A RECORD') then
    AType := drtA
  else if (LValue = 'AAAA') or (LValue = 'AAAA RECORD') or (LValue = 'IPV6') then
    AType := drtAAAA
  else if (LValue = 'CNAME') or (LValue = 'CANONICAL') or (LValue = 'ALIAS') then
    AType := drtCNAME
  else if (LValue = 'MX') or (LValue = 'MAIL') or (LValue = 'MAIL EXCHANGE') then
    AType := drtMX
  else if (LValue = 'TXT') or (LValue = 'TEXT') or (LValue = 'SPF') then
    AType := drtTXT
  else if (LValue = 'NS') or (LValue = 'NAMESERVER') or (LValue = 'NAME SERVER') then
    AType := drtNS
  else if (LValue = 'SOA') or (LValue = 'START OF AUTHORITY') then
    AType := drtSOA
  else if (LValue = 'SRV') or (LValue = 'SERVICE') then
    AType := drtSRV
  else if (LValue = 'PTR') or (LValue = 'POINTER') or (LValue = 'REVERSE') then
    AType := drtPTR
  else if (LValue = 'CAA') or (LValue = 'CERTIFICATION') then
    AType := drtCAA
  else
    Result := False;
end;

function TDNSRecordTypeHelper.RequiresPriority: Boolean;
begin
  Result := Self in [drtMX, drtSRV];
end;

function TDNSRecordTypeHelper.RequiresPort: Boolean;
begin
  Result := Self = drtSRV;
end;

function TDNSRecordTypeHelper.RequiresWeight: Boolean;
begin
  Result := Self = drtSRV;
end;

function TDNSRecordTypeHelper.RequiresFlags: Boolean;
begin
  Result := Self = drtCAA;
end;

function TDNSRecordTypeHelper.RequiresTag: Boolean;
begin
  Result := Self = drtCAA;
end;

function TDNSRecordTypeHelper.IsIPRecord: Boolean;
begin
  Result := Self in [drtA, drtAAAA];
end;

function TDNSRecordTypeHelper.IsNameRecord: Boolean;
begin
  Result := Self in [drtCNAME, drtNS, drtMX, drtPTR];
end;

function TDNSRecordTypeHelper.IsTextRecord: Boolean;
begin
  Result := Self = drtTXT;
end;

function TDNSRecordTypeHelper.GetDefaultTTL: Integer;
begin
  case Self of
    drtNS: Result := 86400;       // 24 hours for name servers
    drtSOA: Result := 86400;      // 24 hours for SOA
    drtMX: Result := 3600;        // 1 hour for mail servers
    drtCNAME: Result := 3600;     // 1 hour for aliases
    drtA, drtAAAA: Result := 300; // 5 minutes for IP addresses (allows faster updates)
    drtTXT: Result := 3600;       // 1 hour for text records
    drtSRV: Result := 3600;       // 1 hour for services
    drtCAA: Result := 86400;      // 24 hours for CAA
    drtPTR: Result := 86400;      // 24 hours for reverse DNS
  else
    Result := 3600;               // Default 1 hour
  end;
end;

function TDNSRecordTypeHelper.GetMaxValueLength: Integer;
begin
  case Self of
    drtA: Result := 15;           // Max IPv4 length: 255.255.255.255
    drtAAAA: Result := 45;        // Max IPv6 length with full notation
    drtTXT: Result := 255;        // TXT record limit per string
    drtCNAME, drtNS, drtMX, drtPTR: Result := 253; // Max DNS name length
    drtSRV: Result := 253;        // Target host max length
    drtCAA: Result := 255;        // CAA value limit
    drtSOA: Result := 512;        // SOA can be longer
  else
    Result := 255;
  end;
end;

function TDNSRecordTypeHelper.GetDefaultPriority: Integer;
begin
  case Self of
    drtMX: Result := 10;
    drtSRV: Result := 0;
  else
    Result := 0;
  end;
end;

function TDNSRecordTypeHelper.ValidateValue(const AValue: string): Boolean;
var
  IPv4Regex, IPv6Regex, DomainRegex: TRegEx;
begin
  Result := False;

  case Self of
    drtA:
      begin
        IPv4Regex := TRegEx.Create('^(\d{1,3}\.){3}\d{1,3}$');
        Result := IPv4Regex.IsMatch(AValue);
        if Result then
        begin
          // Additional validation for each octet
          var Parts := AValue.Split(['.']);
          for var Part in Parts do
            if StrToIntDef(Part, -1) > 255 then
              Exit(False);
        end;
      end;

    drtAAAA:
      begin
        // Simplified IPv6 validation
        IPv6Regex := TRegEx.Create('^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$');
        Result := IPv6Regex.IsMatch(AValue);
      end;

    drtCNAME, drtNS, drtMX, drtPTR:
      begin
        DomainRegex := TRegEx.Create('^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\.?$');
        Result := DomainRegex.IsMatch(AValue) or (AValue = '@');
      end;

    drtTXT:
      Result := Length(AValue) <= GetMaxValueLength;

    drtSRV:
      begin
        // SRV record format validation would be more complex
        // For now, just check it looks like a domain
        DomainRegex := TRegEx.Create('^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.?$');
        Result := DomainRegex.IsMatch(AValue);
      end;

    drtCAA:
      Result := (Length(AValue) > 0) and (Length(AValue) <= GetMaxValueLength);

    drtSOA:
      Result := True; // SOA validation is complex, handled separately

  else
    Result := Length(AValue) > 0;
  end;
end;

function TDNSRecordTypeHelper.GetExampleValue: string;
begin
  case Self of
    drtA: Result := '192.168.1.1';
    drtAAAA: Result := '2001:0db8:85a3:0000:0000:8a2e:0370:7334';
    drtCNAME: Result := 'example.com.';
    drtMX: Result := 'mail.example.com.';
    drtTXT: Result := 'v=spf1 include:_spf.google.com ~all';
    drtNS: Result := 'ns1.example.com.';
    drtSOA: Result := 'ns1.example.com. admin.example.com. 2024010101 3600 1800 604800 86400';
    drtSRV: Result := '10 60 5060 sipserver.example.com.';
    drtPTR: Result := 'host.example.com.';
    drtCAA: Result := '0 issue "letsencrypt.org"';
  else
    Result := '';
  end;
end;

function TDNSRecordTypeHelper.GetRecordIcon: string;
begin
  case Self of
    drtA: Result := '🔢';      // IPv4
    drtAAAA: Result := '6️⃣';    // IPv6
    drtCNAME: Result := '🔗';   // Alias/Link
    drtMX: Result := '📧';      // Mail
    drtTXT: Result := '📝';     // Text
    drtNS: Result := '🌐';      // Name Server
    drtSOA: Result := '👑';     // Authority
    drtSRV: Result := '🎯';     // Service
    drtPTR: Result := '🔄';     // Reverse/Pointer
    drtCAA: Result := '🔒';     // Certificate
  else
    Result := '📋';
  end;
end;

function TDNSRecordTypeHelper.GetRFCNumber: string;
begin
  case Self of
    drtA: Result := 'RFC 1035';
    drtAAAA: Result := 'RFC 3596';
    drtCNAME: Result := 'RFC 1035';
    drtMX: Result := 'RFC 1035';
    drtTXT: Result := 'RFC 1035';
    drtNS: Result := 'RFC 1035';
    drtSOA: Result := 'RFC 1035';
    drtSRV: Result := 'RFC 2782';
    drtPTR: Result := 'RFC 1035';
    drtCAA: Result := 'RFC 8659';
  else
    Result := '';
  end;
end;

function TDNSRecordTypeHelper.GetStandardPort: Integer;
begin
  // Only relevant for SRV records, returns 0 for others
  Result := 0;
  if Self = drtSRV then
    Result := 0; // SRV ports are service-specific
end;

function TDNSRecordTypeHelper.IsDeprecated: Boolean;
begin
  // None of our supported types are deprecated
  Result := False;
end;

function TDNSRecordTypeHelper.IsExperimental: Boolean;
begin
  // CAA was experimental but is now standard
  Result := False;
end;

function TDNSRecordTypeHelper.IsCommonlySupported: Boolean;
begin
  Result := Self in [drtA, drtAAAA, drtCNAME, drtMX, drtTXT, drtNS];
end;

function TDNSRecordTypeHelper.GetMinTTL: Integer;
begin
  // Most providers have a minimum TTL
  case Self of
    drtNS, drtSOA: Result := 3600;  // Usually higher minimum for these
  else
    Result := 60;  // 1 minute minimum for most records
  end;
end;

function TDNSRecordTypeHelper.GetMaxTTL: Integer;
begin
  // Most providers have a maximum TTL
  Result := 2147483647;  // Max int32, some providers use this

  // But practically:
  case Self of
    drtSOA: Result := 2592000;  // 30 days
  else
    Result := 604800;  // 7 days for most records
  end;
end;

{ TDNSRecordTypeArrayHelper }

function TDNSRecordTypeArrayHelper.Contains(AType: TDNSRecordType): Boolean;
var
  LType: TDNSRecordType;
begin
  Result := False;
  for LType in Self do
    if LType = AType then
      Exit(True);
end;

function TDNSRecordTypeArrayHelper.ToString: string;
var
  LType: TDNSRecordType;
  LFirst: Boolean;
begin
  Result := '';
  LFirst := True;
  for LType in Self do
  begin
    if not LFirst then
      Result := Result + ', ';
    Result := Result + LType.ToString;
    LFirst := False;
  end;
end;

procedure TDNSRecordTypeArrayHelper.Add(AType: TDNSRecordType);
begin
  if not Contains(AType) then
  begin
    SetLength(Self, Length(Self) + 1);
    Self[High(Self)] := AType;
  end;
end;

procedure TDNSRecordTypeArrayHelper.Remove(AType: TDNSRecordType);
var
  I, J: Integer;
begin
  for I := 0 to High(Self) do
  begin
    if Self[I] = AType then
    begin
      for J := I to High(Self) - 1 do
        Self[J] := Self[J + 1];
      SetLength(Self, Length(Self) - 1);
      Break;
    end;
  end;
end;

end.

