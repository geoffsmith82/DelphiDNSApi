unit Test.SPF.ExpModifier;

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,
  DNS.SPF.Parser,
  DNS.SPF.Types;

type
  [TestFixture]
  TSpfExpModifierTests = class
  public
    [Test]
    procedure ExpModifier_IsParsed;
  end;

implementation

procedure TSpfExpModifierTests.ExpModifier_IsParsed;
var
  Parser: TSpfParser;
  Ast: TSpfRecordAst;
  Found: Boolean;
begin
  Parser := TSpfParser.Create;
  try
    Ast := Parser.Parse('example.com',
      'v=spf1 ip4:203.0.113.0/24 -all exp=explain.test');

    Found := False;
    for var M in Ast.Modifiers do
      if SameText(M.Name, 'exp') then
      begin
        Found := True;
        Assert.AreEqual('explain.test', M.Value);
      end;

    Assert.IsTrue(Found, 'exp modifier not parsed');
  finally
    Parser.Free;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TSpfExpModifierTests);

end.

