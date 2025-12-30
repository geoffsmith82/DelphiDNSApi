unit Test.SPF.MXMechanism;

interface

uses
  DUnitX.TestFramework,
  DNS.SPF.Engine,
  DNS.SPF.Types,
  Test.SPF.FakeResolver;

type
  [TestFixture]
  TSpfMXMechanismTests = class
  public
    [Test]
    procedure MX_WithCidr_Matches;
  end;

implementation

procedure TSpfMXMechanismTests.MX_WithCidr_Matches;
var
  R: ISpfDnsResolver;
  Engine: TSpfEngine;
  Ctx: TSpfContext;
  Res: TSpfEvaluationResult;
begin
  R := TFakeSpfDnsResolver.Create;
  Engine := TSpfEngine.Create;
  try
    // SPF: allow IPs matching MX A records with /24 mask
    TFakeSpfDnsResolver(R).AddTXT('example.com', [
      'v=spf1 mx/24 -all'
    ]);

    // MX host
    TFakeSpfDnsResolver(R).AddMX('example.com', [
      'mail.example.com'
    ]);

    // A record for MX host
    TFakeSpfDnsResolver(R).AddA('mail.example.com', [
      '203.0.113.10'
    ]);

    Ctx.IpAddress := '203.0.113.200';

    Res := Engine.Evaluate('example.com', Ctx, R);

    Assert.AreEqual(spfPass, Res.Code);
    Assert.IsTrue(Pos('mx', Res.MatchedTerm) > 0);
  finally
    Engine.Free;
    R := nil;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TSpfMXMechanismTests);

end.

