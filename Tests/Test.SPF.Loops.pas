unit Test.SPF.Loops;

interface

uses
  DUnitX.TestFramework,
  DNS.SPF.Engine,
  DNS.SPF.Types,
  Test.SPF.FakeResolver;

type
  [TestFixture]
  TSpfLoopTests = class
  public
    [Test]
    procedure IncludeLoop_Detected;
  end;

implementation

procedure TSpfLoopTests.IncludeLoop_Detected;
var
  R: ISpfDnsResolver;
  Engine: TSpfEngine;
  Ctx: TSpfContext;
  Res: TSpfEvaluationResult;
begin
  R := TFakeSpfDnsResolver.Create;
  Engine := TSpfEngine.Create;
  try
    TFakeSpfDnsResolver(R).AddTXT('a.test', [
      'v=spf1 include:b.test -all'
    ]);
    TFakeSpfDnsResolver(R).AddTXT('b.test', [
      'v=spf1 include:a.test -all'
    ]);

    Ctx.IpAddress := '203.0.113.1';

    Res := Engine.Evaluate('a.test', Ctx, R);

    Assert.AreEqual(spfPermError, Res.Code);
  finally
    Engine.Free;
    R := nil;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TSpfLoopTests);

end.

