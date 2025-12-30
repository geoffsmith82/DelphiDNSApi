// ============================================================================
// Unit: DNS.SPF.Types
// Purpose: Core types, issues, results, DNS resolver interface, and CIDR helpers
// ============================================================================

unit DNS.SPF.Types;

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  System.NetEncoding,
  System.Net.Socket,
  Winapi.Windows,
  Winapi.Winsock2,
  System.RegularExpressions;

type
  // RFC 7208 result codes (plus SPF "none")
  TSpfResultCode = (spfPass, spfFail, spfSoftFail, spfNeutral, spfNone, spfTempError, spfPermError);

  // SPF qualifier prefix
  TSpfQualifier = (qPass, qFail, qSoftFail, qNeutral); // +, -, ~, ?

  TSpfIssueSeverity = (sevInfo, sevWarning, sevError);

  TSpfIssueCode =
  (
    icNotSpf1,
    icMultipleSpfRecords,
    icSyntaxError,
    icInvalidDomain,
    icInvalidIpOrCidr,
    icAllNotLast,
    icMissingAll,
    icTooManyLookups,
    icIncludeLoop,
    icDnsTempError,
    icDnsPermError,
    icMacroSyntaxError
  );

  TSpfIssue = record
    Severity: TSpfIssueSeverity;
    Code: TSpfIssueCode;
    Message: string;
    RawTerm: string;
  end;

  TSpfEvaluationResult = record
    Code: TSpfResultCode;
    MatchedTerm: string;
    Explanation: string;
    DnsLookupsUsed: Integer;
  end;

  // Context for macro expansion + evaluation
  TSpfContext = record
    IpAddress: string;   // required
    MailFrom: string;    // optional: "user@example.com"
    Helo: string;        // optional: "mail.example.com"
  end;

  // DNS query classification
  TDnsStatus = (dnsOk, dnsNoData, dnsNxDomain, dnsTempError, dnsPermError, dnsError);

  // Resolver abstraction (you can wrap your provider/OS DNS here)
  ISpfDnsResolver = interface
    ['{A89A73D5-4B6B-4D8A-8D9A-7B4A8E89DFA4}']
    function QueryTXT(const Name: string; out Txt: TArray<string>): TDnsStatus;
    function QueryA(const Name: string; out Addrs: TArray<string>): TDnsStatus;
    function QueryAAAA(const Name: string; out Addrs: TArray<string>): TDnsStatus;
    function QueryMX(const Name: string; out Hosts: TArray<string>): TDnsStatus;
  end;

  // Parsed mechanism kinds we support
  TSpfMechanismKind = (mkAll, mkIp4, mkIp6, mkA, mkMX, mkInclude, mkExists, mkPtr, mkUnknown);

  TSpfMechanism = record
    Qualifier: TSpfQualifier;
    Kind: TSpfMechanismKind;
    DomainSpec: string; // for a/mx/include/exists/ptr (may contain macros)
    IpOrValue: string;  // ip4/ip6 literal with optional CIDR OR include/exists value
    RawText: string;    // original term text (without v=spf1)
    // For a/mx CIDR lengths (optional) - if 0 then unspecified
    V4Cidr: Integer;
    V6Cidr: Integer;
  end;

  TSpfModifier = record
    Name: string;   // redirect, exp, unknown
    Value: string;
    RawText: string;
  end;

  TSpfRecordAst = record
    Domain: string; // the domain this SPF was loaded for
    Mechanisms: TArray<TSpfMechanism>;
    Modifiers: TArray<TSpfModifier>;
  end;

  TIPv6Bytes = packed record
    Bytes: array[0..15] of Byte;
  end;

function SpfQualifierChar(Q: TSpfQualifier): Char;
function SpfQualifierToResult(Q: TSpfQualifier): TSpfResultCode;

function IsLikelySpfRecord(const Txt: string): Boolean;
function NormalizeTxtConcatenation(const Txt: string): string;

function IsValidDomainLike(const S: string): Boolean;

function TryParseIPv4(const S: string; out Bytes: TArray<Byte>): Boolean;
function TryParseIPv6(const S: string; out Bytes: TArray<Byte>): Boolean;

function TryParseCidr(const S: string; out IsV6: Boolean; out NetBytes: TArray<Byte>; out PrefixLen: Integer): Boolean;
function IpMatchesCidr(const IpBytes, NetBytes: TArray<Byte>; PrefixLen: Integer): Boolean;

implementation

function SpfQualifierChar(Q: TSpfQualifier): Char;
begin
  case Q of
    qPass:     Result := '+';
    qFail:     Result := '-';
    qSoftFail: Result := '~';
    qNeutral:  Result := '?';
  else
    Result := '+';
  end;
end;

function SpfQualifierToResult(Q: TSpfQualifier): TSpfResultCode;
begin
  case Q of
    qPass:     Result := spfPass;
    qFail:     Result := spfFail;
    qSoftFail: Result := spfSoftFail;
    qNeutral:  Result := spfNeutral;
  else
    Result := spfNeutral;
  end;
end;

function IsLikelySpfRecord(const Txt: string): Boolean;
begin
  Result := TRegEx.IsMatch(Trim(Txt), '^(?i)\s*v=spf1(\s|$)');
end;

function NormalizeTxtConcatenation(const Txt: string): string;
begin
  // DNS providers may return quoted chunks; for our purposes we just collapse whitespace.
  Result := Trim(TRegEx.Replace(Txt, '\s+', ' '));
end;

function IsValidDomainLike(const S: string): Boolean;
var
  D: string;
begin
  D := S.Trim;
  if D.EndsWith('.') then
    D := D.Substring(0, D.Length - 1);

  // Simple, pragmatic: labels 1..63, total <=253, allowed [A-Z0-9-], no leading/trailing '-'
  Result := TRegEx.IsMatch(D,
    '^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$'
  );
end;

function TryParseIPv4(const S: string; out Bytes: TArray<Byte>): Boolean;
var
  Parts: TArray<string>;
  I, V: Integer;
begin
  Result := False;
  Bytes := nil;
  Parts := S.Split(['.']);
  if Length(Parts) <> 4 then Exit;

  SetLength(Bytes, 4);
  for I := 0 to 3 do
  begin
    if not TryStrToInt(Parts[I], V) then Exit;
    if (V < 0) or (V > 255) then Exit;
    Bytes[I] := Byte(V);
  end;
  Result := True;
end;

function TryParseIPv6(const S: string; out Bytes: TArray<Byte>): Boolean;
var
  Addr6: TIPv6Bytes;
begin
  SetLength(Bytes, 16);
  Result := inet_pton(AF_INET6, PAnsiChar(AnsiString(S)), @Addr6) = 1;
  if Result then
    Move(Addr6, Bytes[0], 16)
  else
    Bytes := nil;
end;

function TryParseCidr(const S: string; out IsV6: Boolean; out NetBytes: TArray<Byte>; out PrefixLen: Integer): Boolean;
var
  SlashPos: Integer;
  IpPart, PfxPart: string;
  P: Integer;
begin
  Result := False;
  NetBytes := nil;
  PrefixLen := 0;
  IsV6 := False;

  SlashPos := S.IndexOf('/');
  if SlashPos < 0 then
  begin
    // No prefix => /32 or /128 depending on type
    if TryParseIPv4(S, NetBytes) then
    begin
      IsV6 := False;
      PrefixLen := 32;
      Exit(True);
    end;
    if TryParseIPv6(S, NetBytes) then
    begin
      IsV6 := True;
      PrefixLen := 128;
      Exit(True);
    end;
    Exit(False);
  end;

  IpPart := S.Substring(0, SlashPos).Trim;
  PfxPart := S.Substring(SlashPos + 1).Trim;
  if not TryStrToInt(PfxPart, P) then Exit;

  if TryParseIPv4(IpPart, NetBytes) then
  begin
    IsV6 := False;
    if (P < 0) or (P > 32) then Exit(False);
    PrefixLen := P;
    Exit(True);
  end;

  if TryParseIPv6(IpPart, NetBytes) then
  begin
    IsV6 := True;
    if (P < 0) or (P > 128) then Exit(False);
    PrefixLen := P;
    Exit(True);
  end;

  Result := False;
end;

function IpMatchesCidr(const IpBytes, NetBytes: TArray<Byte>; PrefixLen: Integer): Boolean;
var
  FullBytes, RemBits, I: Integer;
  Mask: Byte;
begin
  Result := False;
  if (Length(IpBytes) <> Length(NetBytes)) then Exit;
  if PrefixLen < 0 then Exit;

  FullBytes := PrefixLen div 8;
  RemBits := PrefixLen mod 8;

  for I := 0 to FullBytes - 1 do
    if IpBytes[I] <> NetBytes[I] then Exit(False);

  if RemBits = 0 then
    Exit(True);

  Mask := Byte($FF shl (8 - RemBits));
  Result := (IpBytes[FullBytes] and Mask) = (NetBytes[FullBytes] and Mask);
end;

end.
