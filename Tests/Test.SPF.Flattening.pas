unit Test.SPF.Flattening;

interface

uses
  DUnitX.TestFramework,
  DNS.SPF.Engine,
  DNS.SPF.Types,
  Test.SPF.FakeResolver;

type
  [TestFixture]
  TSpfFlatteningTests = class
  public
    [Test]
    procedure Flatten_SimpleInclude;
  end;

implementation

procedure TSpfFlatteningTests.Flatten_SimpleInclude;
var
  R: ISpfDnsResolver;
  Engine: TSpfEngine;
  F: TSpfFlattenResult;
begin
  R := TFakeSpfDnsResolver.Create;
  Engine := TSpfEngine.Create;
  try
    TFakeSpfDnsResolver(R).AddTXT('example.com', [
      'v=spf1 include:spf.other.test -all'
    ]);

    TFakeSpfDnsResolver(R).AddTXT('spf.other.test', [
      'v=spf1 ip4:203.0.113.0/24 -all'
    ]);

    // Placeholder API — expected shape
    F := Engine.Flatten('example.com', R);

    Assert.IsTrue(Pos('ip4:203.0.113.0/24', F.Txt) > 0);
    Assert.IsFalse(Pos('include:', F.Txt) > 0);
  finally
    Engine.Free;
    R := nil;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TSpfFlatteningTests);

end.

