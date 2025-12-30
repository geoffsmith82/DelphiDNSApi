unit Test.DNS.DMARC.Policy;

interface

uses
  DUnitX.TestFramework,
  DNS.DMARC.Types,
  DNS.DMARC.Parser,
  DNS.DMARC.Policy;

type
  [TestFixture]
  TDmarcPolicyTests = class
  public
    [Test] procedure Parse_ValidMinimalRecord;
    [Test] procedure Parse_MissingPolicy_Fails;

    [Test] procedure Defaults_AppliedCorrectly;

    [Test] procedure SpfAlignment_Strict_Match;
    [Test] procedure SpfAlignment_Strict_NoMatch;
    [Test] procedure SpfAlignment_Relaxed_SubdomainMatch;

    [Test] procedure DkimAlignment_Strict;
    [Test] procedure DkimAlignment_Relaxed;

    [Test] procedure EffectivePolicy_RootDomain;
    [Test] procedure EffectivePolicy_Subdomain;

    [Test] procedure Pct_Zero_DisablesPolicy;
    [Test] procedure Pct_Full_EnablesPolicy;
  end;

implementation

procedure TDmarcPolicyTests.Parse_ValidMinimalRecord;
var
  Parsed: TDmarcParsed;
  Err: string;
begin
  Assert.IsTrue(TryParseDmarc('v=DMARC1; p=none', Parsed, Err), Err);

  Assert.AreEqual(dmpNone, Parsed.Policy);
end;

procedure TDmarcPolicyTests.Parse_MissingPolicy_Fails;
var
  Parsed: TDmarcParsed;
  Err: string;
begin
  Assert.IsFalse(TryParseDmarc('v=DMARC1; rua=mailto:test@example.com', Parsed, Err));
end;


procedure TDmarcPolicyTests.Defaults_AppliedCorrectly;
var
  Parsed: TDmarcParsed;
  Err: string;
begin
  TryParseDmarc('v=DMARC1; p=none', Parsed, Err);

  Assert.AreEqual(daRelaxed, Parsed.Adkim);
  Assert.AreEqual(daRelaxed, Parsed.Aspf);
  Assert.AreEqual(100, Parsed.Pct);
  Assert.AreEqual(dmpNone, Parsed.SubdomainPolicy);
end;


procedure TDmarcPolicyTests.SpfAlignment_Strict_Match;
var
  Parsed: TDmarcParsed;
  Dmarc: TDmarcPolicyContext;
  Err: string;
begin
  TryParseDmarc('v=DMARC1; p=none; aspf=s', Parsed, Err);
  Dmarc := TDmarcPolicyContext.Create(Parsed);
  try
    Assert.IsTrue(Dmarc.IsSpfAligned('example.com', 'example.com'));
  finally
    Dmarc.Free;
  end;
end;


procedure TDmarcPolicyTests.SpfAlignment_Strict_NoMatch;
var
  Parsed: TDmarcParsed;
  Dmarc: TDmarcPolicyContext;
  Err: string;
begin
  TryParseDmarc('v=DMARC1; p=none; aspf=s', Parsed, Err);
  Dmarc := TDmarcPolicyContext.Create(Parsed);
  try
    Assert.IsFalse(Dmarc.IsSpfAligned('mail.example.com', 'example.com'));
  finally
    Dmarc.Free;
  end;
end;

procedure TDmarcPolicyTests.SpfAlignment_Relaxed_SubdomainMatch;
var
  Parsed: TDmarcParsed;
  Dmarc: TDmarcPolicyContext;
  Err: string;
begin
  TryParseDmarc('v=DMARC1; p=none; aspf=r', Parsed, Err);
  Dmarc := TDmarcPolicyContext.Create(Parsed);
  try
    Assert.IsTrue(Dmarc.IsSpfAligned('mail.example.com', 'example.com'));
  finally
    Dmarc.Free;
  end;
end;


procedure TDmarcPolicyTests.DkimAlignment_Strict;
var
  Parsed: TDmarcParsed;
  Dmarc: TDmarcPolicyContext;
  Err: string;
begin
  TryParseDmarc('v=DMARC1; p=none; adkim=s', Parsed, Err);
  Dmarc := TDmarcPolicyContext.Create(Parsed);
  try
    Assert.IsFalse(Dmarc.IsDkimAligned('selector.example.com', 'example.com'));
  finally
    Dmarc.Free;
  end;
end;

procedure TDmarcPolicyTests.DkimAlignment_Relaxed;
var
  Parsed: TDmarcParsed;
  Dmarc: TDmarcPolicyContext;
  Err: string;
begin
  TryParseDmarc('v=DMARC1; p=none; adkim=r', Parsed, Err);
  Dmarc := TDmarcPolicyContext.Create(Parsed);
  try
    Assert.IsTrue(Dmarc.IsDkimAligned('selector.example.com', 'example.com'));
  finally
    Dmarc.Free;
  end;
end;


procedure TDmarcPolicyTests.EffectivePolicy_RootDomain;
var
  Parsed: TDmarcParsed;
  Dmarc: TDmarcPolicyContext;
  Err: string;
begin
  TryParseDmarc('v=DMARC1; p=reject', Parsed, Err);
  Dmarc := TDmarcPolicyContext.Create(Parsed);
  try
    Assert.AreEqual(dmpReject, Dmarc.EffectivePolicy('example.com', 'example.com'));
  finally
    Dmarc.Free;
  end;
end;

procedure TDmarcPolicyTests.EffectivePolicy_Subdomain;
var
  Parsed: TDmarcParsed;
  Dmarc: TDmarcPolicyContext;
  Err: string;
begin
  TryParseDmarc('v=DMARC1; p=reject; sp=none', Parsed, Err);
  Dmarc := TDmarcPolicyContext.Create(Parsed);
  try
    Assert.AreEqual(dmpNone, Dmarc.EffectivePolicy('example.com', 'mail.example.com'));
  finally
    Dmarc.Free;
  end;
end;

procedure TDmarcPolicyTests.Pct_Zero_DisablesPolicy;
var
  Parsed: TDmarcParsed;
  Dmarc: TDmarcPolicyContext;
  Err: string;
begin
  TryParseDmarc('v=DMARC1; p=reject; pct=0', Parsed, Err);
  Dmarc := TDmarcPolicyContext.Create(Parsed);
  try
    Assert.IsFalse(Dmarc.ShouldApplyPolicy);
  finally
    Dmarc.Free;
  end;
end;

procedure TDmarcPolicyTests.Pct_Full_EnablesPolicy;
var
  Parsed: TDmarcParsed;
  Dmarc: TDmarcPolicyContext;
  Err: string;
begin
  TryParseDmarc('v=DMARC1; p=reject; pct=100', Parsed, Err);
  Dmarc := TDmarcPolicyContext.Create(Parsed);
  try
    Assert.IsTrue(Dmarc.ShouldApplyPolicy);
  finally
    Dmarc.Free;
  end;
end;


end.
