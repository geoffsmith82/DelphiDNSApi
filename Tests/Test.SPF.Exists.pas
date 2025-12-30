unit Test.SPF.Exists;

interface

uses
  DUnitX.TestFramework,
  DNS.SPF.Engine,
  DNS.SPF.Types,
  Test.SPF.FakeResolver;

type
  [TestFixture]
  TSpfExistsTests = class
  public
    [Test]
    procedure Exists_NXDomain_DoesNotMatch;

    [Test]
    procedure Exists_NoData_DoesNotMatch;

    [Test]
    procedure Exists_WithARecord_Matches;
  end;

implementation

procedure TSpfExistsTests.Exists_NXDomain_DoesNotMatch;
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
      'v=spf1 exists:nope.test -all'
    ]);

    // no A record added -> NXDOMAIN / NODATA
    Ctx.IpAddress := '203.0.113.1';

    Res := Engine.Evaluate('example.com', Ctx, R);

    Assert.AreEqual(spfFail, Res.Code);
    Assert.IsTrue(Pos('all', Res.MatchedTerm) > 0);
  finally
    Engine.Free;
    R := nil;
  end;
end;

procedure TSpfExistsTests.Exists_NoData_DoesNotMatch;
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
      'v=spf1 exists:empty.test -all'
    ]);

    // Explicitly no A/AAAA data
    TFakeSpfDnsResolver(R).AddA('empty.test', []);

    Ctx.IpAddress := '203.0.113.1';

    Res := Engine.Evaluate('example.com', Ctx, R);

    Assert.AreEqual(spfFail, Res.Code);
  finally
    Engine.Free;
    R := nil;
  end;
end;

procedure TSpfExistsTests.Exists_WithARecord_Matches;
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
      'v=spf1 exists:hit.test -all'
    ]);

    TFakeSpfDnsResolver(R).AddA('hit.test', ['127.0.0.1']);

    Ctx.IpAddress := '203.0.113.1';

    Res := Engine.Evaluate('example.com', Ctx, R);

    Assert.AreEqual(spfPass, Res.Code);
    Assert.IsTrue(Pos('exists', Res.MatchedTerm) > 0);
  finally
    Engine.Free;
    R := nil;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TSpfExistsTests);

end.

