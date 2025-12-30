unit Test.SPF.ExpEvaluation;

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,
  DNS.SPF.Engine,
  DNS.SPF.Types,
  Test.SPF.FakeResolver;

type
  [TestFixture]
  TSpfExpEvaluationTests = class
  public
    [Test]
    procedure ExpModifier_OnFail_ReturnsExplanation;
  end;

implementation

procedure TSpfExpEvaluationTests.ExpModifier_OnFail_ReturnsExplanation;
var
  R: ISpfDnsResolver;
  Engine: TSpfEngine;
  Ctx: TSpfContext;
  Res: TSpfEvaluationResult;
begin
  R := TFakeSpfDnsResolver.Create;
  Engine := TSpfEngine.Create;
  try
    // SPF policy: always fail, but provide explanation
    TFakeSpfDnsResolver(R).AddTXT('example.com', [
      'v=spf1 -all exp=exp.example.com'
    ]);

    // exp= TXT record
    TFakeSpfDnsResolver(R).AddTXT('exp.example.com', [
      'Mail from this host is not permitted'
    ]);

    Ctx.IpAddress := '203.0.113.55';
    Ctx.MailFrom := 'user@example.com';
    Ctx.Helo := 'mail.example.com';

    Res := Engine.Evaluate('example.com', Ctx, R);

    Assert.AreEqual(
      spfFail,
      Res.Code,
      'Expected SPF fail due to -all'
    );

    Assert.IsTrue(
      Pos('not permitted', LowerCase(Res.Explanation)) > 0,
      'exp= explanation was not returned'
    );

    // Optional but useful: exp= costs a DNS lookup
    Assert.IsTrue(
      Res.DnsLookupsUsed >= 2,
      'Expected TXT + exp TXT lookup'
    );
  finally
    Engine.Free;
    R := nil;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TSpfExpEvaluationTests);

end.

