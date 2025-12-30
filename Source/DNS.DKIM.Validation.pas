unit DNS.DKIM.Validation;

interface

uses
  DNS.DKIM.Types,
  DNS.SPF.Types; // for ISpfDnsResolver / TDnsStatus

type
  TDkimValidationResult = record
    Selector: string;
    Domain: string;
    Exists: Boolean;
    IsValid: Boolean;
    Errors: TArray<string>;
    Warnings: TArray<string>;
  end;

function ValidateDkimSelector(const Domain: string; const Selector: string; Resolver: ISpfDnsResolver): TDkimValidationResult;

implementation

uses
  System.SysUtils,
  DNS.DKIM.Parser;

function ValidateDkimSelector(const Domain: string; const Selector: string; Resolver: ISpfDnsResolver): TDkimValidationResult;
var
  Txts: TArray<string>;
  Parsed: TDkimParsed;
  Err: string;
  Status: TDnsStatus;
begin
  Result.Domain := Domain;
  Result.Selector := Selector;
  Result.Exists := False;
  Result.IsValid := False;
  Result.Errors := nil;
  Result.Warnings := nil;

  Status := Resolver.QueryTXT(Selector + '._domainkey.' + Domain, Txts);

  if Status <> dnsOk then
  begin
    Result.Errors := ['No DKIM TXT record found for selector'];
    Exit;
  end;

  Result.Exists := True;

  if Length(Txts) > 1 then
  begin
    Result.Errors := ['Multiple DKIM TXT records found (permerror)'];
    Exit;
  end;

  if not TryParseDkim(Txts[0], Parsed, Err) then
  begin
    Result.Errors := [Err];
    Exit;
  end;

  Result.IsValid := True;

  if Length(Parsed.PublicKey) < 200 then
    Result.Warnings := ['DKIM public key appears unusually short'];
end;

end.

