program SPFTests;

{$IFNDEF TESTINSIGHT}
{$APPTYPE CONSOLE}
{$ENDIF}
{$STRONGLINKTYPES ON}
uses
  System.SysUtils,
  {$IFDEF TESTINSIGHT}
  TestInsight.DUnitX,
  {$ELSE}
  DUnitX.Loggers.Console,
  DUnitX.Loggers.Xml.NUnit,
  {$ENDIF }
  DUnitX.TestFramework,
  Test.DNS.SPF.Fixture in 'Test.DNS.SPF.Fixture.pas',
  DNS.SPF.Builder in '..\Source\DNS.SPF.Builder.pas',
  DNS.SPF.Engine in '..\Source\DNS.SPF.Engine.pas',
  DNS.SPF.Parser in '..\Source\DNS.SPF.Parser.pas',
  DNS.SPF.Types in '..\Source\DNS.SPF.Types.pas',
  Test.SPF.FakeResolver in 'Test.SPF.FakeResolver.pas',
  Test.SPF.Parser in 'Test.SPF.Parser.pas',
  Test.SPF.LookupLimit in 'Test.SPF.LookupLimit.pas',
  Test.SPF.Redirect in 'Test.SPF.Redirect.pas',
  Test.SPF.Macros in 'Test.SPF.Macros.pas',
  Test.SPF.AMechanism in 'Test.SPF.AMechanism.pas',
  Test.SPF.Loops in 'Test.SPF.Loops.pas',
  Test.SPF.MXMechanism in 'Test.SPF.MXMechanism.pas',
  Test.SPF.IPv6 in 'Test.SPF.IPv6.pas',
  Test.SPF.RedirectPrecedence in 'Test.SPF.RedirectPrecedence.pas',
  Test.SPF.Exists in 'Test.SPF.Exists.pas',
  Test.SPF.MultipleTxt in 'Test.SPF.MultipleTxt.pas',
  Test.SPF.ExpModifier in 'Test.SPF.ExpModifier.pas',
  Test.SPF.Flattening in 'Test.SPF.Flattening.pas',
  DNS.SPF.DnsCache in '..\Source\DNS.SPF.DnsCache.pas',
  Test.SPF.ExpEvaluation in 'Test.SPF.ExpEvaluation.pas';

{ keep comment here to protect the following conditional from being removed by the IDE when adding a unit }
{$IFNDEF TESTINSIGHT}
var
  runner: ITestRunner;
  results: IRunResults;
  logger: ITestLogger;
  nunitLogger : ITestLogger;
{$ENDIF}
begin
{$IFDEF TESTINSIGHT}
  TestInsight.DUnitX.RunRegisteredTests;
{$ELSE}
  try
    //Check command line options, will exit if invalid
    TDUnitX.CheckCommandLine;
    //Create the test runner
    runner := TDUnitX.CreateRunner;
    //Tell the runner to use RTTI to find Fixtures
    runner.UseRTTI := True;
    //When true, Assertions must be made during tests;
    runner.FailsOnNoAsserts := False;

    //tell the runner how we will log things
    //Log to the console window if desired
    if TDUnitX.Options.ConsoleMode <> TDunitXConsoleMode.Off then
    begin
      logger := TDUnitXConsoleLogger.Create(TDUnitX.Options.ConsoleMode = TDunitXConsoleMode.Quiet);
      runner.AddLogger(logger);
    end;
    //Generate an NUnit compatible XML File
    nunitLogger := TDUnitXXMLNUnitFileLogger.Create(TDUnitX.Options.XMLOutputFile);
    runner.AddLogger(nunitLogger);

    //Run tests
    results := runner.Execute;
    if not results.AllPassed then
      System.ExitCode := EXIT_ERRORS;

    {$IFNDEF CI}
    //We don't want this happening when running under CI.
    if TDUnitX.Options.ExitBehavior = TDUnitXExitBehavior.Pause then
    begin
      System.Write('Done.. press <Enter> key to quit.');
      System.Readln;
    end;
    {$ENDIF}
  except
    on E: Exception do
      System.Writeln(E.ClassName, ': ', E.Message);
  end;
{$ENDIF}
end.
