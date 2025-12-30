// ============================================================================
// Unit: DNS.SPF.Engine
// Purpose: Domain validation + SPF evaluation with DNS recursion + macro support
// Supports: ip4, ip6, a, mx, include, all, redirect; exists treated as opaque match
// Enforces: 10 lookup budget, include/redirect loop protection, basic macro syntax
// ============================================================================

unit DNS.SPF.Engine;

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  System.RegularExpressions,
  DNS.SPF.Types,
  DNS.SPF.Parser;

type
  ESpfEngineError = class(Exception);

  TSpfFlattenResult = record
    Txt: string;                 // Flattened SPF string (single TXT)
    DnsLookupsUsed: Integer;
    Enumerable: Boolean;         // False if we encountered exists/ptr/macros etc.
    OpaqueTerms: TArray<string>; // What prevented full enumeration
  end;

  TSpfTrace = record
    Steps: TArray<string>;
  end;


  TSpfEngine = class
  private
    FParser: TSpfParser;

    function LoadSpfForDomain(const Domain: string; Resolver: ISpfDnsResolver;
      out SpfTxt: string; out Issues: TArray<TSpfIssue>): Boolean;

    function ExpandMacros(const S, CurrentDomain: string; const Ctx: TSpfContext; out Expanded: string): Boolean;

    function EvaluateDomainInternal(
      const Domain: string;
      const Ctx: TSpfContext;
      Resolver: ISpfDnsResolver;
      var BudgetUsed: Integer;
      const Stack: TList<string>;
      out Issues: TList<TSpfIssue>;
      Trace: TList<string>
    ): TSpfEvaluationResult;

    procedure ConsumeLookup(var BudgetUsed: Integer; const Why: string; Issues: TList<TSpfIssue>; Trace: TList<string>);
    procedure AddIssue(Issues: TList<TSpfIssue>; Code: TSpfIssueCode; const Msg, Raw: string; Severity: TSpfIssueSeverity = sevError);

  public
    constructor Create;
    destructor Destroy; override;

    // Use case 2: pass a domain name and validate published SPF
    function ValidateDomain(const Domain: string; Resolver: ISpfDnsResolver; out Issues: TArray<TSpfIssue>): Boolean;

    // Use case 3: evaluate SPF result for source domain + remote IP (macro-aware via Context)
    function Evaluate(const Domain: string; const Context: TSpfContext; Resolver: ISpfDnsResolver): TSpfEvaluationResult;

    function EvaluateWithTrace(const Domain: string; const Context: TSpfContext;
      Resolver: ISpfDnsResolver; out Trace: TSpfTrace): TSpfEvaluationResult;

    function Flatten(const Domain: string; Resolver: ISpfDnsResolver): TSpfFlattenResult;
  end;

implementation

procedure TraceAdd(const L: TList<string>; const S: string);
begin
  if L <> nil then
    L.Add(S);
end;

constructor TSpfEngine.Create;
begin
  inherited Create;
  FParser := TSpfParser.Create;
end;

destructor TSpfEngine.Destroy;
begin
  FParser.Free;
  inherited Destroy;
end;

procedure TSpfEngine.AddIssue(Issues: TList<TSpfIssue>; Code: TSpfIssueCode; const Msg, Raw: string; Severity: TSpfIssueSeverity);
var
  I: TSpfIssue;
begin
  I.Severity := Severity;
  I.Code := Code;
  I.Message := Msg;
  I.RawTerm := Raw;
  Issues.Add(I);
end;

procedure TSpfEngine.ConsumeLookup(var BudgetUsed: Integer; const Why: string; Issues: TList<TSpfIssue>; Trace: TList<string>);
begin
  Inc(BudgetUsed);
  if True then
    TraceAdd(Trace, 'Consumed: ' + Why);


  if BudgetUsed > 10 then
    AddIssue(Issues, icTooManyLookups, 'SPF exceeded 10 DNS-lookup limit', Why, sevError);
end;

function TSpfEngine.LoadSpfForDomain(
  const Domain: string;
  Resolver: ISpfDnsResolver;
  out SpfTxt: string;
  out Issues: TArray<TSpfIssue>
): Boolean;
var
  Txts: TArray<string>;
  Status: TDnsStatus;
  LIssues: TList<TSpfIssue>;
  SpfStartCount: Integer;
  T: string;
begin
  SpfTxt := '';
  LIssues := TList<TSpfIssue>.Create;
  try
    if not IsValidDomainLike(Domain) then
    begin
      AddIssue(LIssues, icInvalidDomain, 'Invalid domain format', Domain);
      Issues := LIssues.ToArray;
      Exit(False);
    end;

    Status := Resolver.QueryTXT(Domain, Txts);

    case Status of
      dnsOk, dnsNoData, dnsNxDomain:
        begin
          // Count how many SPF records exist
          SpfStartCount := 0;
          for T in Txts do
            if IsLikelySpfRecord(T) then
              Inc(SpfStartCount);

          if SpfStartCount = 0 then
          begin
            // No SPF record
            Issues := LIssues.ToArray;
            Exit(False);
          end;

          if SpfStartCount > 1 then
          begin
            AddIssue(
              LIssues,
              icMultipleSpfRecords,
              'Multiple SPF records found (permerror)',
              Domain
            );
            Issues := LIssues.ToArray;
            Exit(False);
          end;

          // Exactly one SPF record → concatenate ALL TXT strings
          SpfTxt := '';
          for T in Txts do
          begin
            if SpfTxt <> '' then
              SpfTxt := SpfTxt + ' ';
            SpfTxt := SpfTxt + Trim(T);
          end;

          SpfTxt := NormalizeTxtConcatenation(SpfTxt);

          Issues := LIssues.ToArray;
          Exit(True);
        end;

      dnsTempError:
        begin
          AddIssue(
            LIssues,
            icDnsTempError,
            'Temporary DNS error while querying TXT',
            Domain
          );
          Issues := LIssues.ToArray;
          Exit(False);
        end;

      dnsPermError:
        begin
          AddIssue(
            LIssues,
            icDnsPermError,
            'Permanent DNS error while querying TXT',
            Domain
          );
          Issues := LIssues.ToArray;
          Exit(False);
        end;
    end;

    Issues := LIssues.ToArray;
    Result := False;
  finally
    LIssues.Free;
  end;
end;


// Very small (but useful) macro implementation:
// Supports %{i} %{d} %{s} %{h} and literal %%
// Validates macro syntax enough to avoid silent wrong expansions.
function TSpfEngine.ExpandMacros(const S, CurrentDomain: string; const Ctx: TSpfContext; out Expanded: string): Boolean;
var
  I: Integer;
  Ch: Char;
  Key: Char;
  OutStr: TStringBuilder;
  SenderDomain: string;
begin
  Expanded := '';
  Result := True;

  SenderDomain := '';
  if Ctx.MailFrom.Contains('@') then
    SenderDomain := Ctx.MailFrom.Split(['@'])[1]
  else
    SenderDomain := CurrentDomain;

  OutStr := TStringBuilder.Create;
  try
    I := 1;
    while I <= S.Length do
    begin
      Ch := S[I];

      if Ch = '%' then
      begin
        if (I < S.Length) and (S[I + 1] = '%') then
        begin
          OutStr.Append('%');
          Inc(I, 2);
          Continue;
        end;

        // Expect %{x}
        if (I + 2 <= S.Length) and (S[I + 1] = '{') then
        begin
          // find closing }
          if (I + 3 <= S.Length) and (S[I + 3] = '}') then
          begin
            Key := S[I + 2];
            case Key of
              'i': OutStr.Append(Ctx.IpAddress);
              'd': OutStr.Append(CurrentDomain);
              's': OutStr.Append(Ctx.MailFrom);
              'h': OutStr.Append(Ctx.Helo);
            else
              // Unknown macro key: treat as permerror-ish for strict validation
              Result := False;
              Exit;
            end;
            Inc(I, 4);
            Continue;
          end
          else
          begin
            Result := False;
            Exit;
          end;
        end
        else
        begin
          Result := False;
          Exit;
        end;
      end
      else
      begin
        OutStr.Append(Ch);
        Inc(I);
      end;
    end;

    Expanded := OutStr.ToString;
  finally
    OutStr.Free;
  end;
end;

function TSpfEngine.ValidateDomain(const Domain: string; Resolver: ISpfDnsResolver; out Issues: TArray<TSpfIssue>): Boolean;
var
  SpfTxt: string;
  LoadIssues: TArray<TSpfIssue>;
  LIssues: TList<TSpfIssue>;
  Ast: TSpfRecordAst;
  I: Integer;
  AllCount: Integer;
begin
  LIssues := TList<TSpfIssue>.Create;
  try
    if (Resolver = nil) then
    begin
      AddIssue(LIssues, icDnsPermError, 'Resolver is required for ValidateDomain', Domain);
      Issues := LIssues.ToArray;
      Exit(False);
    end;

    if not LoadSpfForDomain(Domain, Resolver, SpfTxt, LoadIssues) then
    begin
      for I := 0 to High(LoadIssues) do
        LIssues.Add(LoadIssues[I]);

      // if no SPF found, that's "none" not invalid; but your use case is "validate it exists and is valid"
      if Length(LoadIssues) = 0 then
        AddIssue(LIssues, icNotSpf1, 'No SPF record found (spf=none)', Domain, sevWarning);

      Issues := LIssues.ToArray;
      Exit(False);
    end;

    try
      Ast := FParser.Parse(Domain, SpfTxt);
    except
      on E: Exception do
      begin
        AddIssue(LIssues, icSyntaxError, 'SPF parse error: ' + E.Message, SpfTxt);
        Issues := LIssues.ToArray;
        Exit(False);
      end;
    end;

    // Offline structural checks: exactly one "all" and it should be last (recommended; most MTAs expect it)
    AllCount := 0;
    for I := 0 to High(Ast.Mechanisms) do
      if Ast.Mechanisms[I].Kind = mkAll then
        Inc(AllCount);

    if AllCount = 0 then
      AddIssue(LIssues, icMissingAll, 'SPF record missing "all" mechanism', SpfTxt);

    if (AllCount > 0) and (Length(Ast.Mechanisms) > 0) and (Ast.Mechanisms[High(Ast.Mechanisms)].Kind <> mkAll) then
      AddIssue(LIssues, icAllNotLast, '"all" mechanism should be last', Ast.Mechanisms[High(Ast.Mechanisms)].RawText);

    // We don’t fully prove 10-lookups here; Evaluate does strict enforcement.
    Issues := LIssues.ToArray;
    Result := Length(Issues) = 0;
  finally
    LIssues.Free;
  end;
end;

function TSpfEngine.Evaluate(const Domain: string; const Context: TSpfContext; Resolver: ISpfDnsResolver): TSpfEvaluationResult;
var
  T: TSpfTrace;
begin
  Result := EvaluateWithTrace(Domain, Context, Resolver, T);
end;


function TSpfEngine.EvaluateDomainInternal(
      const Domain: string;
      const Ctx: TSpfContext;
      Resolver: ISpfDnsResolver;
      var BudgetUsed: Integer;
      const Stack: TList<string>;
      out Issues: TList<TSpfIssue>;
      Trace: TList<string>
    ): TSpfEvaluationResult;
var
  SpfTxt: string;
  LoadIssues: TArray<TSpfIssue>;
  Ast: TSpfRecordAst;
  Mech: TSpfMechanism;
  IpBytes, NetBytes: TArray<Byte>;
  Pfx: Integer;
  Expanded: string;
  AHosts, AAAAHosts, MXHosts: TArray<string>;
  Status: TDnsStatus;

  function MatchIpMechanism(const CidrText: string): Boolean;
  var
    TargetIsV6: Boolean;
  begin
    Result := False;
    if not TryParseCidr(CidrText, TargetIsV6, NetBytes, Pfx) then Exit(False);

    if TargetIsV6 then
    begin
      if not TryParseIPv6(Ctx.IpAddress, IpBytes) then Exit(False);
    end
    else
    begin
      if not TryParseIPv4(Ctx.IpAddress, IpBytes) then Exit(False);
    end;

    Result := IpMatchesCidr(IpBytes, NetBytes, Pfx);
  end;

  function MatchAorMX(const Kind: TSpfMechanismKind; const DomainSpec: string; V4Cidr, V6Cidr: Integer): Boolean;
  var
    D, Dexp: string;
    IpB: TArray<Byte>;
    Host: string;
    TargetNet: TArray<Byte>;
    TargetPfx: Integer;
    DummyIsV6: Boolean;
  begin
    Result := False;

    D := DomainSpec;
    if D = '' then
      D := Domain;

    // macros?
    if not ExpandMacros(D, Domain, Ctx, Dexp) then
    begin
      AddIssue(Issues, icMacroSyntaxError, 'Macro syntax error in domain-spec: ' + D, D);
      Exit(False);
    end;
    if not IsValidDomainLike(Dexp) then
      Exit(False); // invalid domain => mechanism does not match

    if Kind = mkA then
      ConsumeLookup(BudgetUsed, 'a:' + Dexp, Issues, Trace)
    else
      ConsumeLookup(BudgetUsed, 'mx:' + Dexp, Issues, Trace);

    if BudgetUsed > 10 then Exit(False);

    if Kind = mkA then
    begin
      Status := Resolver.QueryA(Dexp, AHosts);
      if Status = dnsTempError then Exit(False);
      Status := Resolver.QueryAAAA(Dexp, AAAAHosts);
      if Status = dnsTempError then Exit(False);

      // check match against returned A/AAAA
      if TryParseIPv4(Ctx.IpAddress, IpB) then
      begin
        for Host in AHosts do
        begin
          // Host here is IP string
          if (V4Cidr > 0) and TryParseCidr(Host + '/' + V4Cidr.ToString, DummyIsV6, TargetNet, TargetPfx) then
          begin
            if IpMatchesCidr(IpB, TargetNet, TargetPfx) then Exit(True);
          end
          else if Host = Ctx.IpAddress then
            Exit(True);
        end;
      end
      else if TryParseIPv6(Ctx.IpAddress, IpB) then
      begin
        for Host in AAAAHosts do
        begin
          if (V6Cidr > 0) and TryParseCidr(Host + '/' + V6Cidr.ToString, DummyIsV6, TargetNet, TargetPfx) then
          begin
            if IpMatchesCidr(IpB, TargetNet, TargetPfx) then Exit(True);
          end
          else if Host = Ctx.IpAddress then
            Exit(True);
        end;
      end;

      Exit(False);
    end;

    // MX: resolve MX hosts then A/AAAA of each host
    Status := Resolver.QueryMX(Dexp, MXHosts);
    if Status = dnsTempError then Exit(False);

    for Host in MXHosts do
    begin
      // NOTE: Counting of underlying A/AAAA queries vs SPF "lookup budget" is nuanced.
      // For predictability we do NOT consume extra budget here; we treat the whole mx evaluation as the 1 lookup.
      Resolver.QueryA(Host, AHosts);
      Resolver.QueryAAAA(Host, AAAAHosts);

      if TryParseIPv4(Ctx.IpAddress, IpB) then
      begin
        for var Aip in AHosts do
        begin
          if (V4Cidr > 0) and TryParseCidr(Aip + '/' + V4Cidr.ToString, DummyIsV6, TargetNet, TargetPfx) then
          begin
            if IpMatchesCidr(IpB, TargetNet, TargetPfx) then Exit(True);
          end
          else if Aip = Ctx.IpAddress then
            Exit(True);
        end;
      end
      else if TryParseIPv6(Ctx.IpAddress, IpB) then
      begin
        for var A6 in AAAAHosts do
        begin
          if (V6Cidr > 0) and TryParseCidr(A6 + '/' + V6Cidr.ToString, DummyIsV6, TargetNet, TargetPfx) then
          begin
            if IpMatchesCidr(IpB, TargetNet, TargetPfx) then Exit(True);
          end
          else if A6 = Ctx.IpAddress then
            Exit(True);
        end;
      end;
    end;

    Result := False;
  end;

  function GetModifierValue(const Name: string; out Val: string): Boolean;
  begin
    Result := False;
    Val := '';
    for var M in Ast.Modifiers do
      if SameText(M.Name, Name) then
      begin
        Val := M.Value;
        Exit(True);
      end;
  end;

var
  RedirectVal, RedirectExpanded: string;
begin
  Result.Code := spfNone;
  Result.MatchedTerm := '';
  Result.Explanation := '';
  Result.DnsLookupsUsed := BudgetUsed;

  if Resolver = nil then
  begin
    Result.Code := spfPermError;
    Result.Explanation := 'Resolver is required for DNS-backed SPF evaluation';
    Exit;
  end;

  // loop detection
  if Stack.Contains(LowerCase(Domain)) then
  begin
    AddIssue(Issues, icIncludeLoop, 'Include/redirect loop detected', Domain);
    Result.Code := spfPermError;
    Result.Explanation := 'Loop detected';
    Exit;
  end;

  Stack.Add(LowerCase(Domain));
  try
    // Fetch SPF record (TXT) for domain: this is effectively a lookup.
    ConsumeLookup(BudgetUsed, 'txt:' + Domain, Issues, Trace);
    if BudgetUsed > 10 then
    begin
      Result.Code := spfPermError;
      Result.Explanation := 'Lookup budget exceeded';
      Exit;
    end;

    if not LoadSpfForDomain(Domain, Resolver, SpfTxt, LoadIssues) then
    begin
      // if no SPF record => none, else temp/perr based on issues
      if Length(LoadIssues) = 0 then
      begin
        Result.Code := spfNone;
        Result.Explanation := 'No SPF record found';
        Exit;
      end;

      // Promote based on DNS issues
      for var X in LoadIssues do
      begin
        if X.Code in [icDnsTempError] then
        begin
          Result.Code := spfTempError;
          Result.Explanation := X.Message;
          Exit;
        end;
        if X.Code in [icDnsPermError, icMultipleSpfRecords, icInvalidDomain] then
        begin
          Result.Code := spfPermError;
          Result.Explanation := X.Message;
          Exit;
        end;
      end;

      Result.Code := spfNone;
      Exit;
    end;

    try
      Ast := FParser.Parse(Domain, SpfTxt);
    except
      on E: Exception do
      begin
        AddIssue(Issues, icSyntaxError, 'SPF parse error: ' + E.Message, SpfTxt);
        Result.Code := spfPermError;
        Result.Explanation := 'SPF parse error';
        Exit;
      end;
    end;

    // Evaluate mechanisms in order; stop on first match.
    for Mech in Ast.Mechanisms do
    begin
      case Mech.Kind of
        mkIp4, mkIp6:
          begin
            if MatchIpMechanism(Mech.IpOrValue) then
            begin
              Result.Code := SpfQualifierToResult(Mech.Qualifier);
              Result.MatchedTerm := Mech.RawText;
              Result.Explanation := 'Matched ' + Mech.RawText;
              Exit;
            end;
          end;

        mkAll:
          begin
            // always matches
            Result.Code := SpfQualifierToResult(Mech.Qualifier);
            Result.MatchedTerm := Mech.RawText;
            Result.Explanation := 'Matched ' + Mech.RawText;

            // If FAIL, attempt exp= (RFC 7208: explanation modifier)
            if Result.Code = spfFail then
            begin
              var ExpVal: string;
              if GetModifierValue('exp', ExpVal) then
              begin
                var ExpDomain: string;
                if ExpandMacros(ExpVal, Domain, Ctx, ExpDomain) and IsValidDomainLike(ExpDomain) then
                begin
                  TraceAdd(Trace, 'EXP -> ' + ExpDomain);

                  // exp causes DNS TXT lookup
                  ConsumeLookup(BudgetUsed, 'exp:' + ExpDomain, Issues, Trace);
                  if BudgetUsed <= 10 then
                  begin
                    var Txts: TArray<string>;
                    var S := Resolver.QueryTXT(ExpDomain, Txts);
                    if (S = dnsOk) and (Length(Txts) > 0) then
                    begin
                      // pick first TXT string (good enough for now)
                      Result.Explanation := NormalizeTxtConcatenation(Txts[0]);
                    end;
                  end;
                end;
              end;
            end;


            Exit;
          end;

        mkA:
          begin
            if MatchAorMX(mkA, Mech.DomainSpec, Mech.V4Cidr, Mech.V6Cidr) then
            begin
              Result.Code := SpfQualifierToResult(Mech.Qualifier);
              Result.MatchedTerm := Mech.RawText;
              Result.Explanation := 'Matched ' + Mech.RawText;
              Exit;
            end;
          end;

        mkMX:
          begin
            if MatchAorMX(mkMX, Mech.DomainSpec, Mech.V4Cidr, Mech.V6Cidr) then
            begin
              Result.Code := SpfQualifierToResult(Mech.Qualifier);
              Result.MatchedTerm := Mech.RawText;
              Result.Explanation := 'Matched ' + Mech.RawText;
              Exit;
            end;
          end;

        mkInclude:
          begin
            // include:<domain> - counts as a lookup when evaluated
            if not ExpandMacros(Mech.DomainSpec, Domain, Ctx, Expanded) then
            begin
              AddIssue(Issues, icMacroSyntaxError, 'Macro syntax error in include domain: ' + Mech.DomainSpec, Mech.RawText);
              Result.Code := spfPermError;
              Result.Explanation := 'Macro error';
              Exit;
            end;

            if not IsValidDomainLike(Expanded) then
            begin
              AddIssue(Issues, icInvalidDomain, 'Invalid include domain: ' + Expanded, Mech.RawText);
              Result.Code := spfPermError;
              Result.Explanation := 'Invalid include domain';
              Exit;
            end;

            ConsumeLookup(BudgetUsed, 'include:' + Expanded, Issues, Trace);
            if BudgetUsed > 10 then
            begin
              Result.Code := spfPermError;
              Result.Explanation := 'Lookup budget exceeded';
              Exit;
            end;

            var Included := EvaluateDomainInternal(Expanded, Ctx, Resolver, BudgetUsed, Stack, Issues, Trace);
            // include matches only if included policy returns "pass"
            if Included.Code = spfPass then
            begin
              Result.Code := SpfQualifierToResult(Mech.Qualifier);
              Result.MatchedTerm := Mech.RawText;
              Result.Explanation := 'Matched include (' + Expanded + ')';
              Exit;
            end
            else if Included.Code in [spfTempError] then
            begin
              Result.Code := spfTempError;
              Result.Explanation := 'Temp error during include evaluation';
              Exit;
            end
            else if Included.Code in [spfPermError] then
            begin
              Result.Code := spfPermError;
              Result.Explanation := 'Perm error during include evaluation';
              Exit;
            end;
          end;

        mkExists:
          begin
            // exists:<domain> requires DNS A lookup and macros; full RFC would do it.
            // Here we implement it minimally: expand macros, then A query; matches if any A record exists.
            if not ExpandMacros(Mech.DomainSpec, Domain, Ctx, Expanded) then
            begin
              AddIssue(Issues, icMacroSyntaxError, 'Macro syntax error in exists domain: ' + Mech.DomainSpec, Mech.RawText);
              Result.Code := spfPermError;
              Exit;
            end;

            ConsumeLookup(BudgetUsed, 'exists:' + Expanded, Issues, Trace);
            if BudgetUsed > 10 then
            begin
              Result.Code := spfPermError;
              Result.Explanation := 'Lookup budget exceeded';
              Exit;
            end;

            Status := Resolver.QueryA(Expanded, AHosts);
            if Status = dnsTempError then
            begin
              Result.Code := spfTempError;
              Result.Explanation := 'DNS temperror during exists';
              Exit;
            end;

            if (Status = dnsOk) and (Length(AHosts) > 0) then
            begin
              Result.Code := SpfQualifierToResult(Mech.Qualifier);
              Result.MatchedTerm := Mech.RawText;
              Result.Explanation := 'Matched exists (' + Expanded + ')';
              Exit;
            end;
          end;

        mkPtr:
          begin
            // ptr is strongly discouraged; many implementations disable.
            // We treat it as permerror if present (strict mode), or you can implement later.
            AddIssue(Issues, icSyntaxError, 'ptr mechanism not supported (discouraged by RFC)', Mech.RawText);
            Result.Code := spfPermError;
            Result.Explanation := 'ptr not supported';
            Exit;
          end;

      else
        // unknown mechanism => permerror if strict; here: permerror to keep "meets standard" goal
        AddIssue(Issues, icSyntaxError, 'Unknown SPF mechanism: ' + Mech.RawText, Mech.RawText);
        Result.Code := spfPermError;
        Result.Explanation := 'Unknown mechanism';
        Exit;
      end;

      // Budget enforcement: if we exceeded, stop
      if BudgetUsed > 10 then
      begin
        Result.Code := spfPermError;
        Result.Explanation := 'Lookup budget exceeded';
        Exit;
      end;
    end;

    // No match: redirect?
    if GetModifierValue('redirect', RedirectVal) then
    begin
      if not ExpandMacros(RedirectVal, Domain, Ctx, RedirectExpanded) then
      begin
        AddIssue(Issues, icMacroSyntaxError, 'Macro syntax error in redirect: ' + RedirectVal, RedirectVal);
        Result.Code := spfPermError;
        Result.Explanation := 'Macro error in redirect';
        Exit;
      end;

      if not IsValidDomainLike(RedirectExpanded) then
      begin
        AddIssue(Issues, icInvalidDomain, 'Invalid redirect domain: ' + RedirectExpanded, RedirectVal);
        Result.Code := spfPermError;
        Result.Explanation := 'Invalid redirect domain';
        Exit;
      end;

      ConsumeLookup(BudgetUsed, 'redirect:' + RedirectExpanded, Issues, Trace);
      if BudgetUsed > 10 then
      begin
        Result.Code := spfPermError;
        Result.Explanation := 'Lookup budget exceeded';
        Exit;
      end;

      var RedirectResult := EvaluateDomainInternal(
        RedirectExpanded,
        Ctx,
        Resolver,
        BudgetUsed,
        Stack,
        Issues,
        Trace
      );

      Result := RedirectResult;
      Result.Explanation :=
        'redirect to ' + RedirectExpanded + ': ' + RedirectResult.Explanation;

      Exit;
    end;

    // If no match and no redirect: neutral
    Result.Code := spfNeutral;
    Result.Explanation := 'No mechanism matched';
  finally
    Stack.Remove(LowerCase(Domain));
  end;
end;

function TSpfEngine.EvaluateWithTrace(const Domain: string; const Context: TSpfContext;
  Resolver: ISpfDnsResolver; out Trace: TSpfTrace): TSpfEvaluationResult;
var
  Stack: TList<string>;
  Issues: TList<TSpfIssue>;
  Budget: Integer;
  TraceList: TList<string>;
begin
  Stack := TList<string>.Create;
  Issues := TList<TSpfIssue>.Create;
  TraceList := TList<string>.Create;
  try
    Budget := 0;
    Result := EvaluateDomainInternal(Domain, Context, Resolver, Budget, Stack, Issues, TraceList);
    Result.DnsLookupsUsed := Budget;

    Trace.Steps := TraceList.ToArray;
  finally
    FreeAndNil(TraceList);
    FreeAndNil(Issues);
    FreeAndNil(Stack);
  end;
end;

function TSpfEngine.Flatten(const Domain: string; Resolver: ISpfDnsResolver): TSpfFlattenResult;
var
  Seen: TDictionary<string, Boolean>;
  Ips4: TList<string>;
  Ips6: TList<string>;
  Opaque: TList<string>;
  Stack: TList<string>;
  Budget: Integer;

  procedure AddOpaque(const S: string);
  begin
    if (Opaque.IndexOf(S) < 0) then
      Opaque.Add(S);
  end;

  procedure FlattenDomain(const D: string);
  var
    SpfTxt: string;
    LoadIssues: TArray<TSpfIssue>;
    Ast: TSpfRecordAst;
    Mech: TSpfMechanism;
    RedirectVal: string;
  begin
    if (Budget > 10) then Exit;

    if Seen.ContainsKey(LowerCase(D)) then Exit;
    Seen.Add(LowerCase(D), True);

    // Fetch SPF record (counts as lookup in our budget model)
    Inc(Budget);
    if Budget > 10 then Exit;

    if not LoadSpfForDomain(D, Resolver, SpfTxt, LoadIssues) then
      Exit;

    Ast := FParser.Parse(D, SpfTxt);

    // collect ip mechanisms + follow includes
    for Mech in Ast.Mechanisms do
    begin
      case Mech.Kind of
        mkIp4:
          if Ips4.IndexOf(Mech.IpOrValue) < 0 then
            Ips4.Add(Mech.IpOrValue);

        mkIp6:
          if Ips6.IndexOf(Mech.IpOrValue) < 0 then
            Ips6.Add(Mech.IpOrValue);

        mkInclude:
          begin
            Inc(Budget);
            if Budget > 10 then Exit;

            // In flattening we cannot expand macros reliably without context
            if (Pos('%{', Mech.DomainSpec) > 0) then
              AddOpaque(Mech.RawText)
            else
              FlattenDomain(Mech.DomainSpec);
          end;

        mkA, mkMX:
          begin
            // We can’t safely enumerate A/MX into CIDRs here unless you want to.
            // For now mark opaque so Enumerable=false and keep going.
            AddOpaque(Mech.RawText);
          end;

        mkExists, mkPtr:
          AddOpaque(Mech.RawText);

        mkUnknown:
          AddOpaque(Mech.RawText);
      end;
    end;

    // redirect only if no mechanisms matched is MTA semantics,
    // but for flattening we treat redirect as "additional policy source"
    // if present.
    RedirectVal := '';
    for var M in Ast.Modifiers do
      if SameText(M.Name, 'redirect') then
      begin
        RedirectVal := M.Value;
        Break;
      end;

    if RedirectVal <> '' then
    begin
      Inc(Budget);
      if Budget > 10 then Exit;

      if (Pos('%{', RedirectVal) > 0) then
        AddOpaque('redirect=' + RedirectVal)
      else
        FlattenDomain(RedirectVal);
    end;
  end;

var
  Parts: TList<string>;
begin
  Seen := TDictionary<string, Boolean>.Create;
  Ips4 := TList<string>.Create;
  Ips6 := TList<string>.Create;
  Opaque := TList<string>.Create;
  Stack := TList<string>.Create;
  Parts := TList<string>.Create;
  try
    Budget := 0;
    FlattenDomain(Domain);

    Parts.Add('v=spf1');

    for var C in Ips4 do
      Parts.Add('ip4:' + C);

    for var C in Ips6 do
      Parts.Add('ip6:' + C);

    // terminal all - default to -all for safety in flattened policies
    Parts.Add('-all');

    Result.Txt := string.Join(' ', Parts.ToArray);
    Result.DnsLookupsUsed := Budget;
    Result.OpaqueTerms := Opaque.ToArray;
    Result.Enumerable := (Opaque.Count = 0) and (Budget <= 10);
  finally
    FreeAndNil(Parts);
    FreeAndNil(Stack);
    FreeAndNil(Opaque);
    FreeAndNil(Ips6);
    FreeAndNil(Ips4);
    FreeAndNil(Seen);
  end;
end;



end.
