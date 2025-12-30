unit Test.SPF.Parser;

interface

uses
  DUnitX.TestFramework,
  DNS.SPF.Engine,
  DNS.SPF.Types,
  Test.SPF.FakeResolver;

type
  [TestFixture]
  TSpfDomainValidationTests = class
  public
    [Test]
    procedure ValidDomain_SingleSpfRecord;

    [Test]
    procedure InvalidDomain_MultipleSpfRecords;
  end;

implementation

procedure TSpfDomainValidationTests.ValidDomain_SingleSpfRecord;
var
  R: TFakeSpfDnsResolver;
  Engine: TSpfEngine;
  Issues: TArray<TSpfIssue>;
begin
  R := TFakeSpfDnsResolver.Create;
  Engine := TSpfEngine.Create;
  try
    R.AddTXT('example.com', ['v=spf1 ip4:203.0.113.0/24 -all']);

    Assert.IsTrue(Engine.ValidateDomain('example.com', R, Issues), 'SPF should validate cleanly');
  finally
    Engine.Free;
    R := nil;
  end;
end;

procedure TSpfDomainValidationTests.InvalidDomain_MultipleSpfRecords;
var
  R: TFakeSpfDnsResolver;
  Engine: TSpfEngine;
  Issues: TArray<TSpfIssue>;
begin
  R := TFakeSpfDnsResolver.Create;
  Engine := TSpfEngine.Create;
  try
    R.AddTXT('example.com', ['v=spf1 ip4:203.0.113.0/24 -all', 'v=spf1 include:_spf.google.com -all']);

    Assert.IsFalse(Engine.ValidateDomain('example.com', R, Issues));

    Assert.IsTrue(Length(Issues) > 0);
    Assert.AreEqual(icMultipleSpfRecords, Issues[0].Code);
  finally
    Engine.Free;
    R := nil;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TSpfDomainValidationTests);

end.

