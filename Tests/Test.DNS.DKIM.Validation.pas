unit Test.DNS.DKIM.Validation;

interface

uses
  DUnitX.TestFramework,
  DNS.DKIM.Types,
  DNS.DKIM.Parser,
  DNS.DKIM.Validation,
  Test.DKIM.FakeResolver;

type
  [TestFixture]
  TDkimValidationTests = class
  private
    Resolver: TFakeDkimDnsResolver;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;

    [Test] procedure NoRecord_Fails;
    [Test] procedure MultipleRecords_PermError;
    [Test] procedure InvalidRecord_Fails;
    [Test] procedure ValidRecord_Passes;
    [Test] procedure ShortKey_Warns;
  end;

implementation

procedure TDkimValidationTests.Setup;
begin
  Resolver := TFakeDkimDnsResolver.Create;
end;

procedure TDkimValidationTests.TearDown;
begin
  Resolver := nil; // interface refcount
end;

procedure TDkimValidationTests.NoRecord_Fails;
var
  R: TDkimValidationResult;
begin
  R := ValidateDkimSelector('example.com', 'selector1', Resolver);

  Assert.IsFalse(R.Exists);
  Assert.IsFalse(R.IsValid);
end;

procedure TDkimValidationTests.MultipleRecords_PermError;
var
  R: TDkimValidationResult;
begin
  Resolver.AddTxt('selector1._domainkey.example.com', ['v=DKIM1; p=AAA', 'v=DKIM1; p=BBB']);

  R := ValidateDkimSelector('example.com', 'selector1', Resolver);

  Assert.IsTrue(R.Exists);
  Assert.IsFalse(R.IsValid);
  Assert.IsTrue(Length(R.Errors) > 0);
end;

procedure TDkimValidationTests.InvalidRecord_Fails;
var
  R: TDkimValidationResult;
begin
  Resolver.AddTxt('selector1._domainkey.example.com', ['v=DKIM1; k=rsa'] (* missing p= *));

  R := ValidateDkimSelector('example.com', 'selector1', Resolver);

  Assert.IsFalse(R.IsValid);
  Assert.IsTrue(Length(R.Errors) > 0);
end;

procedure TDkimValidationTests.ValidRecord_Passes;
var
  R: TDkimValidationResult;
begin
  Resolver.AddTxt('selector1._domainkey.example.com', ['v=DKIM1; k=rsa; p=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789']);

  R := ValidateDkimSelector('example.com', 'selector1', Resolver);

  Assert.IsTrue(R.Exists);
  Assert.IsTrue(R.IsValid);
end;

procedure TDkimValidationTests.ShortKey_Warns;
var
  R: TDkimValidationResult;
begin
  Resolver.AddTxt('selector1._domainkey.example.com', ['v=DKIM1; p=ABC']);

  R := ValidateDkimSelector('example.com', 'selector1', Resolver);

  Assert.IsTrue(R.IsValid);
  Assert.IsTrue(Length(R.Warnings) > 0);
end;

initialization
  TDUnitX.RegisterTestFixture(TDkimValidationTests);


end.
