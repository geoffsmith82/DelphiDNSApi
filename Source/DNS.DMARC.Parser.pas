unit DNS.DMARC.Parser;

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  DNS.Txt.KeyValue,
  DNS.DMARC.Types;

function TryParseDmarc(
  const Txt: string;
  out RecordOut: TDmarcParsed;
  out Error: string
): Boolean;

implementation

function ParsePolicy(const S: string; out P: TDmarcPolicy): Boolean;
begin
  if SameText(S, 'none') then P := dmpNone
  else if SameText(S, 'quarantine') then P := dmpQuarantine
  else if SameText(S, 'reject') then P := dmpReject
  else Exit(False);
  Result := True;
end;

function ParseAlignment(const S: string; out A: TDmarcAlignment): Boolean;
begin
  if SameText(S, 'r') then A := daRelaxed
  else if SameText(S, 's') then A := daStrict
  else Exit(False);
  Result := True;
end;

function SplitUriList(const S: string): TArray<string>;
begin
  Result := S.Split([',']);
  for var I := 0 to High(Result) do
    Result[I] := Trim(Result[I]);
end;

function TryParseDmarc(
  const Txt: string;
  out RecordOut: TDmarcParsed;
  out Error: string
): Boolean;
var
  Pairs: TTxtKvPairs;
  Issues: TTxtKvIssues;
  Pair: TTxtKvPair;
  HasPolicy: Boolean;
begin
  FillChar(RecordOut, SizeOf(RecordOut), 0);
  Error := '';
  HasPolicy := False;

  // Defaults per RFC
  RecordOut.Adkim := daRelaxed;
  RecordOut.Aspf := daRelaxed;
  RecordOut.Pct := 100;
  RecordOut.SubdomainPolicy := dmpNone;

  if not ParseTxtKeyValueList(Txt, Pairs, Issues) then
  begin
    Error := 'Invalid DMARC TXT syntax';
    Exit(False);
  end;

  for Pair in Pairs do
  begin
    if Pair.Key = 'v' then
      RecordOut.Version := Pair.Value

    else if Pair.Key = 'p' then
    begin
      if not ParsePolicy(Pair.Value, RecordOut.Policy) then
      begin
        Error := 'Invalid DMARC policy value';
        Exit(False);
      end;
      HasPolicy := True;
    end

    else if Pair.Key = 'sp' then
      ParsePolicy(Pair.Value, RecordOut.SubdomainPolicy)

    else if Pair.Key = 'adkim' then
      ParseAlignment(Pair.Value, RecordOut.Adkim)

    else if Pair.Key = 'aspf' then
      ParseAlignment(Pair.Value, RecordOut.Aspf)

    else if Pair.Key = 'pct' then
      TryStrToInt(Pair.Value, RecordOut.Pct)

    else if Pair.Key = 'rua' then
      RecordOut.Rua := SplitUriList(Pair.Value)

    else if Pair.Key = 'ruf' then
      RecordOut.Ruf := SplitUriList(Pair.Value)

    else if Pair.Key = 'fo' then
      RecordOut.Fo := SplitUriList(Pair.Value);
  end;

  if not SameText(RecordOut.Version, 'DMARC1') then
  begin
    Error := 'Missing or invalid DMARC version';
    Exit(False);
  end;

  if not HasPolicy then
  begin
    Error := 'Missing DMARC policy (p=)';
    Exit(False);
  end;

  Result := True;
end;



end.

