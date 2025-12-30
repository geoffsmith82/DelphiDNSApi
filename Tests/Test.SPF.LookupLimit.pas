unit Test.SPF.LookupLimit;

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,
  DNS.SPF.Engine,
  DNS.SPF.Types,
  Test.SPF.FakeResolver;

type
  [TestFixture]
  TSpfLookupLimitTests = class
  public
    [Test]
    procedure IncludeChain_ExceedsLookupLimit_PermError;
  end;

implementation

procedure TSpfLookupLimitTests.IncludeChain_ExceedsLookupLimit_PermError;
var
  R: ISpfDnsResolver;
  Engine: TSpfEngine;
  Ctx: TSpfContext;
  I: Integer;
  Domain, Next: string;
  Res: TSpfEvaluationResult;
begin
  R := TFakeSpfDnsResolver.Create;
  Engine := TSpfEngine.Create;
  try
    // Build include chain: d1 -> d2 -> ... -> d12
    for I := 1 to 12 do
    begin
      Domain := Format('d%d.test', [I]);
      Next := Format('d%d.test', [I + 1]);

      if I < 12 then
        TFakeSpfDnsResolver(R).AddTXT(Domain,
          ['v=spf1 include:' + Next + ' -all'])
      else
        TFakeSpfDnsResolver(R).AddTXT(Domain,
          ['v=spf1 ip4:203.0.113.0/24 -all']);
    end;

    Ctx.IpAddress := '203.0.113.5';

    Res := Engine.Evaluate('d1.test', Ctx, R);

    Assert.AreEqual(spfPermError, Res.Code);
    Assert.IsTrue(Res.DnsLookupsUsed > 10);
  finally
    Engine.Free;
    R := nil;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TSpfLookupLimitTests);

end.

