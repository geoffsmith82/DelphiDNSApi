unit Test.SPF.MultipleTxt;

interface

uses
  DUnitX.TestFramework,
  DNS.SPF.Engine,
  DNS.SPF.Types,
  Test.SPF.FakeResolver;

type
  [TestFixture]
  TSpfMultipleTxtTests = class
  public
    [Test]
    procedure MultipleSpfTxt_PermError;
  end;

implementation

procedure TSpfMultipleTxtTests.MultipleSpfTxt_PermError;
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
      'v=spf1 ip4:203.0.113.0/24 -all',
      'v=spf1 include:_spf.google.com -all'
    ]);

    Ctx.IpAddress := '203.0.113.1';

    Res := Engine.Evaluate('example.com', Ctx, R);

    Assert.AreEqual(spfPermError, Res.Code);
  finally
    Engine.Free;
    R := nil;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TSpfMultipleTxtTests);

end.

