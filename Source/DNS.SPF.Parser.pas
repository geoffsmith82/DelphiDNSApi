// ============================================================================
// Unit: DNS.SPF.Parser
// Purpose: Parse a single SPF TXT string into an AST (mechanisms + modifiers)
// ============================================================================

unit DNS.SPF.Parser;

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  System.RegularExpressions,
  DNS.SPF.Types;

type
  ESpfParseError = class(Exception);

  TSpfParser = class
  public
    function Parse(const Domain, SpfTxt: string): TSpfRecordAst;
  end;

implementation

function ParseQualifier(var Term: string): TSpfQualifier;
begin
  Result := qPass;
  if Term = '' then Exit;

  case Term[Low(string)] of
    '+': begin Result := qPass;     Term := Term.Substring(1); end;
    '-': begin Result := qFail;     Term := Term.Substring(1); end;
    '~': begin Result := qSoftFail; Term := Term.Substring(1); end;
    '?': begin Result := qNeutral;  Term := Term.Substring(1); end;
  end;
end;

function MechanismKindFromName(const Name: string): TSpfMechanismKind;
var
  N: string;
begin
  N := LowerCase(Name);
  if N = 'all' then Exit(mkAll);
  if N = 'ip4' then Exit(mkIp4);
  if N = 'ip6' then Exit(mkIp6);
  if N = 'a' then Exit(mkA);
  if N = 'mx' then Exit(mkMX);
  if N = 'include' then Exit(mkInclude);
  if N = 'exists' then Exit(mkExists);
  if N = 'ptr' then Exit(mkPtr);
  Result := mkUnknown;
end;

procedure ParseDualCidrSuffix(const Suffix: string; out V4, V6: Integer);
var
  Parts: TArray<string>;
begin
  V4 := 0;
  V6 := 0;
  if Suffix = '' then Exit;

  // suffix formats: "/24", "/24//64", "//64"
  if not Suffix.StartsWith('/') then Exit;

  Parts := Suffix.Split(['/']);
  // Examples:
  // "/24" => ['', '24']
  // "/24//64" => ['', '24', '', '64']
  // "//64" => ['', '', '64']
  if Length(Parts) = 2 then
    TryStrToInt(Parts[1], V4)
  else if Length(Parts) = 4 then
  begin
    if Parts[1] <> '' then TryStrToInt(Parts[1], V4);
    if Parts[3] <> '' then TryStrToInt(Parts[3], V6);
  end
  else if Length(Parts) = 3 then
  begin
    // "//64" => ['', '', '64']
    if Parts[2] <> '' then TryStrToInt(Parts[2], V6);
  end;
end;

function TSpfParser.Parse(const Domain, SpfTxt: string): TSpfRecordAst;
var
  Txt, Body: string;
  Tokens: TArray<string>;
  Terms: TList<string>;
  Mechs: TList<TSpfMechanism>;
  Mods: TList<TSpfModifier>;
  I: Integer;
  Tok, Term, Name, Value, CidrSuffix: string;
  EqPos, ColonPos, SlashPos: Integer;
  Q: TSpfQualifier;
  M: TSpfMechanism;
  Modif: TSpfModifier;
begin
  Txt := NormalizeTxtConcatenation(SpfTxt);
  if not IsLikelySpfRecord(Txt) then
    raise ESpfParseError.Create('Not an SPF record');

  // strip leading v=spf1
  Body := Trim(TRegEx.Replace(Txt, '^(?i)\s*v=spf1\s*', '', [roIgnoreCase]));

  Terms := TList<string>.Create;
  Mechs := TList<TSpfMechanism>.Create;
  Mods := TList<TSpfModifier>.Create;
  try
    Tokens := Body.Split([' '], TStringSplitOptions.ExcludeEmpty);
    for Tok in Tokens do
      Terms.Add(Tok);

    for I := 0 to Terms.Count - 1 do
    begin
      Term := Terms[I].Trim;
      if Term = '' then Continue;

      // Modifier? name=value
      EqPos := Term.IndexOf('=');
      if EqPos > 0 then
      begin
        Modif.Name := LowerCase(Term.Substring(0, EqPos));
        Modif.Value := Term.Substring(EqPos + 1);
        Modif.RawText := Term;
        Mods.Add(Modif);
        Continue;
      end;

      // Mechanism (maybe with qualifier)
      Q := ParseQualifier(Term);

      // name[:value][cidr-suffix] for a/mx only cidr-suffix allowed per RFC
      // ip4:addr[/pfx] handled in value itself
      ColonPos := Term.IndexOf(':');
      SlashPos := Term.IndexOf('/');

      Name := Term;
      Value := '';
      CidrSuffix := '';

      if ColonPos > 0 then
      begin
        Name := Term.Substring(0, ColonPos);
        Value := Term.Substring(ColonPos + 1);
      end;

      // Handle a/mx CIDR suffix in both forms:
      //   a/24//64
      //   a:example.com/24//64
      //   mx/24
      //   mx:example.com/24
      var
        BaseName: string;

      BaseName := LowerCase(Name);

      // If there's no ":" but there is a "/", then Name might be "a/24" or "mx/24//64"
      if (ColonPos < 0) and (SlashPos > 0) then
        BaseName := LowerCase(Name.Substring(0, SlashPos));

      if (BaseName = 'a') or (BaseName = 'mx') then
      begin
        // Case 1: a:domain/24//64  (CIDR suffix is part of Value)
        SlashPos := Value.IndexOf('/');
        if SlashPos >= 0 then
        begin
          CidrSuffix := Value.Substring(SlashPos);
          Value := Value.Substring(0, SlashPos);
          Name := BaseName;
        end
        else
        begin
          // Case 2: a/24//64 (CIDR suffix is part of Term, no Value)
          SlashPos := Term.IndexOf('/');
          if SlashPos > 0 then
          begin
            CidrSuffix := Term.Substring(SlashPos);
            Name := BaseName;
            Value := '';
          end;
        end;
      end;

      FillChar(M, SizeOf(M), 0);
      M.Qualifier := Q;
      M.Kind := MechanismKindFromName(Name);
      M.RawText := Terms[I];

      case M.Kind of
        mkAll:
          begin
            // no params
          end;
        mkIp4, mkIp6:
          begin
            if Value = '' then
              raise ESpfParseError.Create('Missing value for ' + Name);
            M.IpOrValue := Value;
          end;
        mkInclude, mkExists, mkPtr:
          begin
            if Value = '' then
              raise ESpfParseError.Create('Missing domain for ' + Name);
            M.DomainSpec := Value;
          end;
        mkA, mkMX:
          begin
            // Value can be empty (defaults to current domain)
            M.DomainSpec := Value;
            ParseDualCidrSuffix(CidrSuffix, M.V4Cidr, M.V6Cidr);
          end;
      else
        // unknown mechanism - preserve raw
      end;

      Mechs.Add(M);
    end;

    Result.Domain := Domain;
    Result.Mechanisms := Mechs.ToArray;
    Result.Modifiers := Mods.ToArray;
  finally
    FreeAndNil(Terms);
    FreeAndNil(Mechs);
    FreeAndNil(Mods);
  end;
end;

end.
