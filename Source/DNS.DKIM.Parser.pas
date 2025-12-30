unit DNS.DKIM.Parser;

interface

uses
  DNS.DKIM.Types;

function TryParseDkim(const Txt: string; out Parsed: TDkimParsed; out Error: string): Boolean;

implementation

uses
  System.SysUtils,
  DNS.Txt.KeyValue;

function TryParseDkim(const Txt: string; out Parsed: TDkimParsed; out Error: string): Boolean;
var
  Pairs: TTxtKvPairs;
  Issues: TTxtKvIssues;
  Pair: TTxtKvPair;
begin
  FillChar(Parsed, SizeOf(Parsed), 0);
  Error := '';

  if not ParseTxtKeyValueList(Txt, Pairs, Issues) then
  begin
    Error := 'Invalid DKIM TXT syntax';
    Exit(False);
  end;

  for Pair in Pairs do
  begin
    if Pair.Key = 'v' then
      Parsed.Version := Pair.Value

    else if Pair.Key = 'p' then
      Parsed.PublicKey := Pair.Value

    else if Pair.Key = 'k' then
    begin
      if SameText(Pair.Value, 'rsa') then
        Parsed.KeyType := dktRsa
      else if SameText(Pair.Value, 'ed25519') then
        Parsed.KeyType := dktEd25519
      else
        Parsed.KeyType := dktUnknown;
    end

    else if Pair.Key = 't' then
      Parsed.Flags := Pair.Value.Split([':'])

    else if Pair.Key = 'h' then
      Parsed.Hashes := Pair.Value.Split([':'])

    else if Pair.Key = 'n' then
      Parsed.Notes := Pair.Value;
  end;

  if not SameText(Parsed.Version, 'DKIM1') then
  begin
    Error := 'Missing or invalid DKIM version';
    Exit(False);
  end;

  if Parsed.PublicKey = '' then
  begin
    Error := 'Missing DKIM public key (p=)';
    Exit(False);
  end;

  Result := True;
end;

end.

