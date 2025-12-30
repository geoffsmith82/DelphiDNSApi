unit DNS.DMARC.Validation;

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  DNS.DMARC.Parser,
  DNS.DMARC.Types;


type
  TDmarcValidationSeverity = (
    dvsError,
    dvsWarning,
    dvsInfo
  );

  TDmarcValidationMessage = record
    Severity: TDmarcValidationSeverity;
    Code: string;
    Message: string;
  end;

  TDmarcValidationMessages = TArray<TDmarcValidationMessage>;

  TDmarcValidationResult = record
    Exists: Boolean;
    IsValid: Boolean;
    Messages: TDmarcValidationMessages;
  end;

  function ValidateDmarcRecord(const Domain: string; const TxtRecords: TArray<string>): TDmarcValidationResult;

implementation

function Msg(Sev: TDmarcValidationSeverity; const Code, Text: string): TDmarcValidationMessage;
begin
  Result.Severity := Sev;
  Result.Code := Code;
  Result.Message := Text;
end;

function ValidateDmarcRecord(const Domain: string; const TxtRecords: TArray<string>): TDmarcValidationResult;
var
  Parsed: TDmarcParsed;
  Err: string;
  Msgs: TList<TDmarcValidationMessage>;
begin
  Msgs := TList<TDmarcValidationMessage>.Create;
  try
    Result.Exists := Length(TxtRecords) > 0;

    if not Result.Exists then
    begin
      Msgs.Add(Msg(dvsInfo, 'dmarc.missing', 'No DMARC record found'));
      Result.IsValid := False;
      Result.Messages := Msgs.ToArray;
      Exit;
    end;

    if Length(TxtRecords) > 1 then
    begin
      Msgs.Add(Msg(dvsError, 'dmarc.multiple', 'Multiple DMARC records found (permerror)'));
      Result.IsValid := False;
      Result.Messages := Msgs.ToArray;
      Exit;
    end;

    if not TryParseDmarc(TxtRecords[0], Parsed, Err) then
    begin
      Msgs.Add(Msg(dvsError, 'dmarc.invalid', 'Invalid DMARC record: ' + Err));
      Result.IsValid := False;
      Result.Messages := Msgs.ToArray;
      Exit;
    end;

    // Valid DMARC
    Result.IsValid := True;
    Msgs.Add(Msg(dvsInfo, 'dmarc.present', 'DMARC record present and syntactically valid'));

    // Policy warnings
    if Parsed.Policy = dmpNone then
      Msgs.Add(Msg(dvsWarning, 'dmarc.policy.none', 'Policy is p=none (monitoring only)'));

    if Parsed.Pct < 100 then
      Msgs.Add(Msg(dvsWarning, 'dmarc.pct.partial', Format('Policy applies to only %d%% of mail', [Parsed.Pct])));

    // Reporting
    if Length(Parsed.Rua) = 0 then
      Msgs.Add(Msg(dvsWarning, 'dmarc.no.rua', 'No aggregate reporting (rua) configured'))
    else
      Msgs.Add(Msg(dvsInfo, 'dmarc.reporting', 'Aggregate reporting enabled'));

    // Subdomain policy
    if (Parsed.SubdomainPolicy <> Parsed.Policy) and
       (Parsed.SubdomainPolicy < Parsed.Policy) then
      Msgs.Add(Msg(dvsWarning, 'dmarc.sp.weaker', 'Subdomain policy is weaker than main policy'));

    // Strict alignment surprises
    if Parsed.Adkim = daStrict then
      Msgs.Add(Msg(dvsWarning, 'dmarc.adkim.strict', 'Strict DKIM alignment may cause unexpected failures'));

    if Parsed.Aspf = daStrict then
      Msgs.Add(Msg(dvsWarning, 'dmarc.aspf.strict', 'Strict SPF alignment may cause unexpected failures'));

    Result.Messages := Msgs.ToArray;
  finally
    FreeAndNil(Msgs);
  end;
end;

end.
