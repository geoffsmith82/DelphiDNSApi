unit Test.DNS.Txt.KeyValue;

interface

uses
  DUnitX.TestFramework,
  DNS.Txt.KeyValue
  ;

type
[TestFixture]
TTxtKeyValueParserTests = class
public
  [Test]
  procedure BasicParse;

  [Test]
  procedure IgnoresEmptySegments;

  [Test]
  procedure DetectsDuplicates;
end;


implementation

procedure TTxtKeyValueParserTests.BasicParse;
var
  Pairs: TTxtKvPairs;
  Issues: TTxtKvIssues;
begin
  Assert.IsTrue(
    ParseTxtKeyValueList(
      'v=DMARC1; p=reject; rua=mailto:test@example.com',
      Pairs,
      Issues
    )
  );

  Assert.AreEqual<Integer>(3, Length(Pairs));
  Assert.AreEqual('v', Pairs[0].Key);
  Assert.AreEqual('DMARC1', Pairs[0].Value);
end;

procedure TTxtKeyValueParserTests.IgnoresEmptySegments;
var
  Pairs: TTxtKvPairs;
  Issues: TTxtKvIssues;
begin
  ParseTxtKeyValueList('v=DMARC1;;p=none;', Pairs, Issues);

  Assert.AreEqual<Integer>(2, Length(Pairs));
end;

procedure TTxtKeyValueParserTests.DetectsDuplicates;
var
  Pairs: TTxtKvPairs;
  Issues: TTxtKvIssues;
begin
  ParseTxtKeyValueList('v=DMARC1; p=none; p=reject', Pairs, Issues);

  Assert.IsTrue(Length(Issues) > 0);
end;

initialization
  TDUnitX.RegisterTestFixture(TTxtKeyValueParserTests);

end.
