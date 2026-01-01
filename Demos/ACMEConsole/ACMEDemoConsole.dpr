program ACMEDemoConsole;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  DNS.Azure in '..\..\Source\DNS.Azure.pas',
  DNS.Base in '..\..\Source\DNS.Base.pas',
  DNS.Bunny in '..\..\Source\DNS.Bunny.pas',
  DNS.Cloudflare in '..\..\Source\DNS.Cloudflare.pas',
  DNS.DigitalOcean in '..\..\Source\DNS.DigitalOcean.pas',
  DNS.Google in '..\..\Source\DNS.Google.pas',
  DNS.Helpers in '..\..\Source\DNS.Helpers.pas',
  DNS.Route53 in '..\..\Source\DNS.Route53.pas',
  DNS.Vultr in '..\..\Source\DNS.Vultr.pas',
  ACME.TaurusCrypto in 'ACME.TaurusCrypto.pas',
  ACME.Client in 'ACME.Client.pas',
  ACME.Client.CmdLine in 'ACME.Client.CmdLine.pas',
  ACME.Client.Dns01 in 'ACME.Client.Dns01.pas',
  ACME.Client.Types in 'ACME.Client.Types.pas',
  ACME.Client.Http01 in 'ACME.Client.Http01.pas';

begin
  ACME.Client.CmdLine.Run;
end.

