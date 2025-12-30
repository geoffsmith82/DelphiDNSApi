unit Test.SPF.MultiStringTxt;

interface

uses
  DUnitX.TestFramework,
  DNS.SPF.Engine,
  DNS.SPF.Types,
  Test.SPF.FakeResolver;

type
  [TestFixture]
  TSpfMultiStringTxtTests = class
  public
    [Test]
    procedure SingleSpfRecord_SplitAcrossTxtStrings_IsConcatenated;
    [Test]
    procedure TwoSpfStarts_InTxtStrings_IsPermError;
  end;

implementation

procedure TSpfMultiStringTxtTests.SingleSpfRecord_SplitAcrossTxtStrings_IsConcatenated;
var
  R: ISpfDnsResolver;
  Engine: TSpfEngine;
  Ctx: TSpfContext;
  Res: TSpfEvaluationResult;
begin
  R := TFakeSpfDnsResolver.Create;
  Engine := TSpfEngine.Create;
  try
    {
      DNS TXT records as they commonly appear in the wild:

      example.com TXT
        "v=spf1 ip4:203.0.113.0/24"
        " include:_spf.other.test -all"
    }

    TFakeSpfDnsResolver(R).AddTXT('example.com', [
      'v=spf1 ip4:203.0.113.0/24',
      ' include:_spf.other.test -all'
    ]);

    TFakeSpfDnsResolver(R).AddTXT('_spf.other.test', [
      'v=spf1 ip4:192.0.2.0/24 -all'
    ]);

    // IP allowed via the first ip4 mechanism
    Ctx.IpAddress := '203.0.113.42';
    Ctx.MailFrom := 'user@example.com';
    Ctx.Helo := 'mail.example.com';

    Res := Engine.Evaluate('example.com', Ctx, R);

    Assert.AreEqual(
      spfPass,
      Res.Code,
      'Multi-string SPF record should be concatenated and evaluated'
    );

    Assert.IsTrue(
      Pos('ip4:203.0.113.0/24', Res.MatchedTerm) > 0,
      'Expected match from concatenated SPF record'
    );
  finally
    Engine.Free;
    R := nil;
  end;
end;

procedure TSpfMultiStringTxtTests.TwoSpfStarts_InTxtStrings_IsPermError;
var
  R: ISpfDnsResolver;
  Engine: TSpfEngine;
  Ctx: TSpfContext;
  Res: TSpfEvaluationResult;
begin
  R := TFakeSpfDnsResolver.Create;
  Engine := TSpfEngine.Create;
  try
    {
      Invalid SPF configuration:

      example.com TXT
        "v=spf1 ip4:203.0.113.0/24 -all"
        "v=spf1 include:_spf.other.test -all"
    }

    TFakeSpfDnsResolver(R).AddTXT('example.com', [
      'v=spf1 ip4:203.0.113.0/24 -all',
      'v=spf1 include:_spf.other.test -all'
    ]);

    Ctx.IpAddress := '203.0.113.42';
    Ctx.MailFrom := 'user@example.com';
    Ctx.Helo := 'mail.example.com';

    Res := Engine.Evaluate('example.com', Ctx, R);

    Assert.AreEqual(
      spfPermError,
      Res.Code,
      'Multiple SPF records must result in permerror'
    );
  finally
    Engine.Free;
    R := nil;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TSpfMultiStringTxtTests);

end.

