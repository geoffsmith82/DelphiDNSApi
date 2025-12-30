unit Test.SPF.Redirect;

interface

uses
  DUnitX.TestFramework,
  DNS.SPF.Engine,
  DNS.SPF.Types,
  Test.SPF.FakeResolver;

type
  [TestFixture]
  TSpfRedirectTests = class
  public
    [Test]
    procedure Redirect_WhenNoMatch_DelegatesPolicy;
  end;

implementation

procedure TSpfRedirectTests.Redirect_WhenNoMatch_DelegatesPolicy;
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
      'v=spf1 redirect=other.test'
    ]);

    TFakeSpfDnsResolver(R).AddTXT('other.test', [
      'v=spf1 ip4:192.0.2.0/24 -all'
    ]);

    Ctx.IpAddress := '192.0.2.10';

    Res := Engine.Evaluate('example.com', Ctx, R);

    Assert.AreEqual(spfPass, Res.Code);
    Assert.IsTrue(Pos('redirect', Res.Explanation) > 0);
  finally
    Engine.Free;
    R := nil;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TSpfRedirectTests);

end.

