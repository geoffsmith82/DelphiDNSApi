unit DNS.DMARC.Policy;

interface

uses
  DNS.DMARC.Types;

type
  TDmarcPolicyContext = class
  private
    FParsed: TDmarcParsed;

    function DomainsAlignRelaxed(const A, B: string): Boolean;
    function DomainsAlignStrict(const A, B: string): Boolean;

  public
    constructor Create(const Parsed: TDmarcParsed);

    function EffectivePolicy(
      const OrganizationalDomain: string;
      const HeaderFromDomain: string
    ): TDmarcPolicy;

    function IsSpfAligned(
      const MailFromDomain: string;
      const HeaderFromDomain: string
    ): Boolean;

    function IsDkimAligned(
      const DkimDomain: string;
      const HeaderFromDomain: string
    ): Boolean;

    function ShouldApplyPolicy: Boolean;

    property Parsed: TDmarcParsed read FParsed;
  end;

implementation

uses
  System.SysUtils;

constructor TDmarcPolicyContext.Create(const Parsed: TDmarcParsed);
begin
  inherited Create;
  FParsed := Parsed;
end;

function TDmarcPolicyContext.DomainsAlignStrict(
  const A, B: string
): Boolean;
begin
  Result := SameText(A, B);
end;

function TDmarcPolicyContext.DomainsAlignRelaxed(
  const A, B: string
): Boolean;
begin
  // Relaxed = same organizational domain
  // (you can later replace this with a PSL-based check)
  Result := SameText(A, B) or
            A.EndsWith('.' + B) or
            B.EndsWith('.' + A);
end;

function TDmarcPolicyContext.IsSpfAligned(
  const MailFromDomain: string;
  const HeaderFromDomain: string
): Boolean;
begin
  if FParsed.Aspf = daStrict then
    Result := DomainsAlignStrict(MailFromDomain, HeaderFromDomain)
  else
    Result := DomainsAlignRelaxed(MailFromDomain, HeaderFromDomain);
end;

function TDmarcPolicyContext.IsDkimAligned(
  const DkimDomain: string;
  const HeaderFromDomain: string
): Boolean;
begin
  if FParsed.Adkim = daStrict then
    Result := DomainsAlignStrict(DkimDomain, HeaderFromDomain)
  else
    Result := DomainsAlignRelaxed(DkimDomain, HeaderFromDomain);
end;

function TDmarcPolicyContext.EffectivePolicy(
  const OrganizationalDomain: string;
  const HeaderFromDomain: string
): TDmarcPolicy;
begin
  if SameText(OrganizationalDomain, HeaderFromDomain) then
    Exit(FParsed.Policy);

  // Subdomain case
  Result := FParsed.SubdomainPolicy;
end;

function TDmarcPolicyContext.ShouldApplyPolicy: Boolean;
begin
  if FParsed.Pct >= 100 then
    Exit(True);

  if FParsed.Pct <= 0 then
    Exit(False);

  // Deterministic randomization could be added later
  Result := True;
end;


end.
