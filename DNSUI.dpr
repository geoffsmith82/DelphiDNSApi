program DNSUI;

uses
  System.StartUpCopy,
  FMX.Forms,
  DNS.Base in 'DNS.Base.pas',
  DNS.Helpers in 'DNS.Helpers.pas',
  DNS.Vultr in 'DNS.Vultr.pas',
  DNS.DigitalOcean in 'DNS.DigitalOcean.pas',
  DNS.Azure in 'DNS.Azure.pas',
  DNS.UI.Main in 'DNS.UI.Main.pas',
  DNS.Cloudflare in 'DNS.Cloudflare.pas',
  DNS.Google in 'DNS.Google.pas',
  DNS.Bunny in 'DNS.Bunny.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TMainForm, MainForm);
  Application.Run;
end.
