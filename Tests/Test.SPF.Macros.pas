unit Test.SPF.Macros;

interface

uses
  DUnitX.TestFramework,
  DNS.SPF.Engine,
  DNS.SPF.Types,
  Test.SPF.FakeResolver;

type
  [TestFixture]
  TSpfMacroTests = class
  public
    [Test]
    procedure Exists_UsesIpMacro;
  end;

implementation

procedure TSpfMacroTests.Exists_UsesIpMacro;
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
      'v=spf1 exists:%{i}.spf.test -all'
    ]);

    // %{i} expands to 203.0.113.5
    TFakeSpfDnsResolver(R).AddA('203.0.113.5.spf.test', [
      '127.0.0.1'
    ]);

    Ctx.IpAddress := '203.0.113.5';

    Res := Engine.Evaluate('example.com', Ctx, R);

    Assert.AreEqual(spfPass, Res.Code);
    Assert.IsTrue(Pos('exists', Res.MatchedTerm) > 0);
  finally
    Engine.Free;
    R := nil;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TSpfMacroTests);

end.

