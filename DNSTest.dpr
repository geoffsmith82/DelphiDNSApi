program DNSTest;

uses
  System.StartUpCopy,
  FMX.Forms,
  DNS.Base in 'DNS.Base.pas',
  DNS.Vultr in 'DNS.Vultr.pas',
  DNS.Helpers in 'DNS.Helpers.pas',
  DNS.UI.Main in 'DNS.UI.Main.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TMainForm, MainForm);
  Application.Run;
end.
