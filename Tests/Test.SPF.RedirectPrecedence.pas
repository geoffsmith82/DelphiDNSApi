unit Test.SPF.RedirectPrecedence;

interface

uses
  DUnitX.TestFramework,
  DNS.SPF.Engine,
  DNS.SPF.Types,
  Test.SPF.FakeResolver;

type
  [TestFixture]
  TSpfRedirectPrecedenceTests = class
  public
    [Test]
    procedure All_Prevents_Redirect;
  end;

implementation

procedure TSpfRedirectPrecedenceTests.All_Prevents_Redirect;
var
  R: ISpfDnsResolver;
  Engine: TSpfEngine;
  Ctx: TSpfContext;
  Res: TSpfEvaluationResult;
begin
  R := TFakeSpfDnsResolver.Create;
  Engine := TSpfEngine.Create;
  try
    TFakeSpfDnsResolver(R).AddTXT('example.com', [
      'v=spf1 -all redirect=other.test'
    ]);

    TFakeSpfDnsResolver(R).AddTXT('other.test', [
      'v=spf1 ip4:203.0.113.0/24 -all'
    ]);

    Ctx.IpAddress := '203.0.113.10';

    Res := Engine.Evaluate('example.com', Ctx, R);

    // -all should short-circuit; redirect must NOT be evaluated
    Assert.AreEqual(spfFail, Res.Code);
    Assert.IsTrue(Pos('all', Res.MatchedTerm) > 0);
  finally
    Engine.Free;
    R := nil;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TSpfRedirectPrecedenceTests);

end.

