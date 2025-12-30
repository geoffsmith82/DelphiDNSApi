// ============================================================================
// Unit: DNS.SPF.Builder
// Purpose: Safe SPF builder that guarantees a valid SPF string (offline rules)
// ============================================================================

unit DNS.SPF.Builder;

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  DNS.SPF.Types;

type
  ESpfBuildError = class(Exception);

  TSpfBuilder = class
  private
    FTerms: TList<string>;
    FHasAll: Boolean;
    FAllQualifier: TSpfQualifier;
    function BuildInternal: string;
  public
    constructor Create;
    destructor Destroy; override;

    procedure AddIp4(const Cidr: string; Qualifier: TSpfQualifier = qPass);
    procedure AddIp6(const Cidr: string; Qualifier: TSpfQualifier = qPass);
    procedure AddInclude(const Domain: string; Qualifier: TSpfQualifier = qPass);
    procedure AddA(const DomainSpec: string = ''; V4Cidr: Integer = 0; V6Cidr: Integer = 0; Qualifier: TSpfQualifier = qPass);
    procedure AddMX(const DomainSpec: string = ''; V4Cidr: Integer = 0; V6Cidr: Integer = 0; Qualifier: TSpfQualifier = qPass);

    procedure SetAll(Qualifier: TSpfQualifier);

    function Validate: TArray<TSpfIssue>;
    function Build: string; // raises if invalid
  end;

implementation

constructor TSpfBuilder.Create;
begin
  inherited Create;
  FTerms := TList<string>.Create;
  FHasAll := False;
  FAllQualifier := qFail;
end;

destructor TSpfBuilder.Destroy;
begin
  FTerms.Free;
  inherited Destroy;
end;

procedure TSpfBuilder.AddIp4(const Cidr: string; Qualifier: TSpfQualifier);
begin
  FTerms.Add(SpfQualifierChar(Qualifier) + 'ip4:' + Cidr);
end;

procedure TSpfBuilder.AddIp6(const Cidr: string; Qualifier: TSpfQualifier);
begin
  FTerms.Add(SpfQualifierChar(Qualifier) + 'ip6:' + Cidr);
end;

procedure TSpfBuilder.AddInclude(const Domain: string; Qualifier: TSpfQualifier);
begin
  FTerms.Add(SpfQualifierChar(Qualifier) + 'include:' + Domain);
end;

procedure TSpfBuilder.AddA(const DomainSpec: string; V4Cidr, V6Cidr: Integer; Qualifier: TSpfQualifier);
var
  Suffix: string;
begin
  Suffix := '';
  if (V4Cidr > 0) or (V6Cidr > 0) then
  begin
    if V4Cidr > 0 then
      Suffix := '/' + V4Cidr.ToString
    else
      Suffix := '/';

    if V6Cidr > 0 then
      Suffix := Suffix + '//' + V6Cidr.ToString;
  end;

  if DomainSpec = '' then
    FTerms.Add(SpfQualifierChar(Qualifier) + 'a' + Suffix)
  else
    FTerms.Add(SpfQualifierChar(Qualifier) + 'a:' + DomainSpec + Suffix);
end;

procedure TSpfBuilder.AddMX(const DomainSpec: string; V4Cidr, V6Cidr: Integer; Qualifier: TSpfQualifier);
var
  Suffix: string;
begin
  Suffix := '';
  if (V4Cidr > 0) or (V6Cidr > 0) then
  begin
    if V4Cidr > 0 then
      Suffix := '/' + V4Cidr.ToString
    else
      Suffix := '/';

    if V6Cidr > 0 then
      Suffix := Suffix + '//' + V6Cidr.ToString;
  end;

  if DomainSpec = '' then
    FTerms.Add(SpfQualifierChar(Qualifier) + 'mx' + Suffix)
  else
    FTerms.Add(SpfQualifierChar(Qualifier) + 'mx:' + DomainSpec + Suffix);
end;

procedure TSpfBuilder.SetAll(Qualifier: TSpfQualifier);
begin
  FHasAll := True;
  FAllQualifier := Qualifier;
end;

function TSpfBuilder.Validate: TArray<TSpfIssue>;
var
  Issues: TList<TSpfIssue>;
  Txt: string;
  DummyV6: Boolean;
  Net: TArray<Byte>;
  Pfx: Integer;
  I: Integer;
  Term: string;
  Lookups: Integer;

  procedure AddIssue(Code: TSpfIssueCode; const Msg, Raw: string);
  var
    X: TSpfIssue;
  begin
    X.Severity := sevError;
    X.Code := Code;
    X.Message := Msg;
    X.RawTerm := Raw;
    Issues.Add(X);
  end;

  function IsLookupTerm(const T: string): Boolean;
  var
    L: string;
  begin
    L := LowerCase(T);

    Result :=
      (Pos('include:', L) = 1) or
      (Pos('exists:', L) = 1) or
      (Pos('redirect=', L) = 1) or

      // a / mx (with optional qualifier)
      (Pos('a', L) = 1) or
      (Pos('+a', L) = 1) or
      (Pos('-a', L) = 1) or
      (Pos('~a', L) = 1) or
      (Pos('?a', L) = 1) or

      (Pos('mx', L) = 1) or
      (Pos('+mx', L) = 1) or
      (Pos('-mx', L) = 1) or
      (Pos('~mx', L) = 1) or
      (Pos('?mx', L) = 1);
  end;


begin
  Issues := TList<TSpfIssue>.Create;
  try
    if not FHasAll then
      AddIssue(icMissingAll, 'SPF should include an "all" mechanism', '');

    Lookups := 0;
    for I := 0 to FTerms.Count - 1 do
    begin
      Term := FTerms[I];

      if Term.Contains('ip4:') then
      begin
        if not TryParseCidr(Term.Substring(Term.IndexOf('ip4:') + 4), DummyV6, Net, Pfx) or DummyV6 then
          AddIssue(icInvalidIpOrCidr, 'Invalid ip4 CIDR', Term);
      end;

      if Term.Contains('ip6:') then
      begin
        if not TryParseCidr(Term.Substring(Term.IndexOf('ip6:') + 4), DummyV6, Net, Pfx) or (not DummyV6) then
          AddIssue(icInvalidIpOrCidr, 'Invalid ip6 CIDR', Term);
      end;

      if Term.Contains('include:') then
      begin
        if not IsValidDomainLike(Term.Substring(Term.IndexOf('include:') + 8)) then
          AddIssue(icInvalidDomain, 'Invalid include domain', Term);
      end;

      if IsLookupTerm(Term) then
        Inc(Lookups);
    end;

    // add "all" term last
    Txt := BuildInternal;
    if Length(Txt) > 255 then
      AddIssue(icSyntaxError, 'SPF TXT exceeds 255 characters (single-string). Consider shortening policy.', Txt);

    if Lookups > 10 then
      AddIssue(icTooManyLookups, 'SPF likely exceeds 10 lookup limit (static estimate).', Txt);

    Result := Issues.ToArray;
  finally
    Issues.Free;
  end;
end;

function TSpfBuilder.BuildInternal: string;
var
  Parts: TList<string>;
  I: Integer;
begin
  Parts := TList<string>.Create;
  try
    Parts.Add('v=spf1');

    for I := 0 to FTerms.Count - 1 do
      Parts.Add(FTerms[I]);

    // "all" must be last
    Parts.Add(SpfQualifierChar(FAllQualifier) + 'all');

    Result := string.Join(' ', Parts.ToArray);
  finally
    Parts.Free;
  end;
end;

function TSpfBuilder.Build: string;
var
  Issues: TArray<TSpfIssue>;
  Parts: TList<string>;
  I: Integer;
begin
  Issues := Validate;
  if Length(Issues) > 0 then
    raise ESpfBuildError.Create(Issues[0].Message);

  Parts := TList<string>.Create;
  try
    Parts.Add('v=spf1');
    for I := 0 to FTerms.Count - 1 do
      Parts.Add(FTerms[I]);

    // Ensure all is last
    Parts.Add(SpfQualifierChar(FAllQualifier) + 'all');

    Result := string.Join(' ', Parts.ToArray);
  finally
    Parts.Free;
  end;
end;

end.
