program DNSUI;

uses
  System.StartUpCopy,
  FMX.Forms,
  DNS.UI.Main in 'DNS.UI.Main.pas',
  DNS.Azure in '..\..\Source\DNS.Azure.pas',
  DNS.Base in '..\..\Source\DNS.Base.pas',
  DNS.Bunny in '..\..\Source\DNS.Bunny.pas',
  DNS.Cloudflare in '..\..\Source\DNS.Cloudflare.pas',
  DNS.DigitalOcean in '..\..\Source\DNS.DigitalOcean.pas',
  DNS.Google in '..\..\Source\DNS.Google.pas',
  DNS.Helpers in '..\..\Source\DNS.Helpers.pas',
  DNS.Route53 in '..\..\Source\DNS.Route53.pas',
  DNS.Vultr in '..\..\Source\DNS.Vultr.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TMainForm, MainForm);
  Application.Run;
end.
