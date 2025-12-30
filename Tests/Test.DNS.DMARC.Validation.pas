unit Test.DNS.DMARC.Validation;

interface

uses
  DUnitX.TestFramework,
  DNS.DMARC.Types,
  DNS.DMARC.Parser,
  DNS.DMARC.Policy,
  DNS.DMARC.Validation;

type
  [TestFixture]
  TDmarcValidationTests = class
  public
    [Test] procedure NoRecord_InfoOnly;
    [Test] procedure MultipleRecords_Error;
    [Test] procedure ValidRejectPolicy_NoErrors;
    [Test] procedure PctWarning;
  end;

implementation

procedure TDmarcValidationTests.NoRecord_InfoOnly;
var
  R: TDmarcValidationResult;
begin
  R := ValidateDmarcRecord('example.com', []);
  Assert.IsFalse(R.IsValid);
end;

procedure TDmarcValidationTests.MultipleRecords_Error;
var
  R: TDmarcValidationResult;
begin
  R := ValidateDmarcRecord('example.com', ['v=DMARC1; p=none', 'v=DMARC1; p=reject']);
  Assert.IsFalse(R.IsValid);
end;

procedure TDmarcValidationTests.ValidRejectPolicy_NoErrors;
var
  R: TDmarcValidationResult;
begin
  R := ValidateDmarcRecord('example.com', ['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']);
  Assert.IsTrue(R.IsValid);
end;

procedure TDmarcValidationTests.PctWarning;
var
  R: TDmarcValidationResult;
begin
  R := ValidateDmarcRecord('example.com', ['v=DMARC1; p=reject; pct=50']);
  Assert.IsTrue(Length(R.Messages) > 0);
end;


end.
