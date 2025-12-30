unit Test.SPF.IPv6;

interface

uses
  DUnitX.TestFramework,
  DNS.SPF.Engine,
  DNS.SPF.Types,
  Test.SPF.FakeResolver;

type
  [TestFixture]
  TSpfIPv6Tests = class
  public
    [Test]
    procedure Ip6_Matches;

    [Test]
    procedure A_WithIPv6Cidr_Matches;
  end;

implementation

procedure TSpfIPv6Tests.Ip6_Matches;
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
      'v=spf1 ip6:2001:db8::/32 -all'
    ]);

    Ctx.IpAddress := '2001:db8:abcd::1';

    Res := Engine.Evaluate('example.com', Ctx, R);

    Assert.AreEqual(spfPass, Res.Code);
    Assert.IsTrue(Pos('ip6:', Res.MatchedTerm) > 0);
  finally
    Engine.Free;
    R := nil;
  end;
end;

procedure TSpfIPv6Tests.A_WithIPv6Cidr_Matches;
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
      'v=spf1 a//64 -all'
    ]);

    TFakeSpfDnsResolver(R).AddAAAA('example.com', [
      '2001:db8:abcd::1'
    ]);

    Ctx.IpAddress := '2001:db8:abcd::999';

    Res := Engine.Evaluate('example.com', Ctx, R);

    Assert.AreEqual(spfPass, Res.Code);
    Assert.IsTrue(Pos('a', Res.MatchedTerm) > 0);
  finally
    Engine.Free;
    R := nil;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TSpfIPv6Tests);

end.

