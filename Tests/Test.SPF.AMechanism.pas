unit Test.SPF.AMechanism;

interface

uses
  DUnitX.TestFramework,
  DNS.SPF.Engine,
  DNS.SPF.Types,
  Test.SPF.FakeResolver;

type
  [TestFixture]
  TSpfAMechanismTests = class
  public
    [Test]
    procedure A_WithCidr_Matches;
  end;

implementation

procedure TSpfAMechanismTests.A_WithCidr_Matches;
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
      'v=spf1 a/24 -all'
    ]);

    TFakeSpfDnsResolver(R).AddA('example.com', [
      '203.0.113.1'
    ]);

    Ctx.IpAddress := '203.0.113.200';

    Res := Engine.Evaluate('example.com', Ctx, R);

    Assert.AreEqual(spfPass, Res.Code);
    Assert.IsTrue(Pos('a', Res.MatchedTerm) > 0);
  finally
    Engine.Free;
    R := nil;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TSpfAMechanismTests);

end.

