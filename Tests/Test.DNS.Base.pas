unit Test.DNS.Base;

interface

uses
  System.SysUtils,
  System.Classes,
  System.Generics.Collections,
  DUnitX.TestFramework,
  DNS.Base,
  DNS.Helpers
  ;


type
  TDnsProviderCapabilities = record
    SupportsAAAA: Boolean;
    SupportsSRV: Boolean;
    SupportsCAA: Boolean;
  end;


type
  TDnsProviderTestsBase = class abstract
  private
    FClient: TBaseDNSProvider;
    FZoneName: string;
  protected
    function CreateClient: TBaseDNSProvider; virtual; abstract;

    // NEW: provider-specific domain handling
    function RootTestDomain: string; virtual; abstract;
    function SupportsSubZones: Boolean; virtual;

    function CreateTestZoneName: string;

    function Capabilities: TDnsProviderCapabilities; virtual;
  public
    [Setup]
    procedure Setup;

    [TearDown]
    procedure TearDown;

    // Zone tests
    [Test] procedure List_Zones_Does_Not_Raise;
    [Test] procedure Create_And_Delete_Zone;
    [Test] procedure List_Zones_Contains_Created_Zone;

    // Record tests
    [Test] procedure Create_Edit_Delete_A_Record;
    [Test] procedure Create_Delete_TXT_Record;
    [Test] procedure Create_Delete_CNAME_Record;
    [Test] procedure Create_Delete_MX_Record;

    [Test] procedure Create_Delete_AAAA_Record;

    // tests unchanged
  end;


implementation

function TDnsProviderTestsBase.SupportsSubZones: Boolean;
begin
  Result := False;
end;

function TDnsProviderTestsBase.Capabilities: TDnsProviderCapabilities;
begin
  Result.SupportsAAAA := True;
  Result.SupportsSRV  := False;
  Result.SupportsCAA  := False;
end;

function TDnsProviderTestsBase.CreateTestZoneName: string;
var
  G: TGUID;
  Token: string;
begin
//  if SupportsSubZones then
//  begin
//    CreateGUID(G);
//    Token := GUIDToString(G);
//    Token := Token.Replace('{', '').Replace('}', '').Replace('-', '');
//    Result := 'test-' + Copy(Token, 1, 8) + '.' + RootTestDomain;
//  end
//  else
    Result := RootTestDomain;
end;

procedure TDnsProviderTestsBase.Setup;
var
  Zones: TObjectList<TDNSZone>;
begin
  FClient := CreateClient;
  Assert.IsNotNull(FClient);

  FZoneName := CreateTestZoneName;

  // For providers that support sub-zones, ensure the test zone exists.
//  if SupportsSubZones then
  begin
    Zones := FClient.ListZones;
    try
      if not Zones.Contains(FZoneName) then
      begin
        FClient.CreateZone(FZoneName);

        // Route53 can be eventually consistent; wait briefly for visibility.
        var Attempt: Integer;
        for Attempt := 1 to 10 do
        begin
          Zones.Free;
          Zones := FClient.ListZones;
          if Zones.Contains(FZoneName) then
            Break;
          TThread.Sleep(500);
        end;
      end;
    finally
      FreeAndNil(Zones);
    end;
  end;
end;

procedure TDnsProviderTestsBase.TearDown;
begin
  if Assigned(FClient) then
  begin
    try
      if SupportsSubZones then
        FClient.DeleteZone(FZoneName);
    except
      // swallow cleanup errors
    end;
    FClient.Free;
  end;
end;

procedure TDnsProviderTestsBase.List_Zones_Does_Not_Raise;
var
  Zones: TObjectList<TDNSZone>;
begin
  Zones := FClient.ListZones;
  Zones.Free;
end;

procedure TDnsProviderTestsBase.Create_And_Delete_Zone;
var
  Zones: TObjectList<TDNSZone>;
  LZone: TDNSZone;
begin
  // Creating/deleting a root zone can be destructive; only do this
  // for providers configured to use sub-zones.
//  if not SupportsSubZones then
//    Exit;

  Zones := FClient.ListZones;
  try
    if Zones.Contains(FZoneName) then
      FClient.DeleteZone(FZoneName);
  finally
    Zones.Free;
  end;

  LZone := FClient.CreateZone(FZoneName);
  try
    Assert.IsNotEmpty(LZone.Id);

    // Route53 can be eventually consistent; retry list.
    var Found := False;
    var Attempt: Integer;
    for Attempt := 1 to 10 do
    begin
      Zones := FClient.ListZones;
      try
        Found := Zones.Contains(FZoneName);
      finally
        Zones.Free;
      end;

      if Found then
        Break;

      TThread.Sleep(500);
    end;

    Assert.IsTrue(Found);
  finally
    LZone.Free;
  end;

  Assert.IsTrue(FClient.DeleteZone(FZoneName));
end;

procedure TDnsProviderTestsBase.List_Zones_Contains_Created_Zone;
var
  LZone : TDNSZone;
begin
  LZone := FClient.GetZone(FZoneName);
  try
    Assert.IsTrue(Length(LZone.Id) > 0);
  finally
    FreeAndNil(LZone);
  end;
end;

procedure TDnsProviderTestsBase.Create_Edit_Delete_A_Record;
var
  LDNSRecord: TDNSRecord;
  LCreatedDNSRecord: TDNSRecord;
begin
  LDNSRecord := TDNSRecord.Create;
  try
    LDNSRecord.Name := 'www';
    LDNSRecord.RecordType := drtA;
    LDNSRecord.Value := '1.2.3.4';
    LDNSRecord.TTL := 300;
    LCreatedDNSRecord := FClient.CreateRecord(FZoneName, LDNSRecord);
    Assert.IsNotEmpty(LCreatedDNSRecord.Id);

    LCreatedDNSRecord.Value := '5.6.7.8';
    LCreatedDNSRecord.TTL := 600;

    FClient.UpdateRecord(FZoneName, LCreatedDNSRecord);

    FClient.DeleteRecord(FZoneName, LCreatedDNSRecord.Id);
  finally
    FreeAndNil(LDNSRecord);
    FreeAndNil(LCreatedDNSRecord);
  end;
end;

procedure TDnsProviderTestsBase.Create_Delete_TXT_Record;
var
  LDNSRecord: TDNSRecord;
  LCreatedDNSRecord: TDNSRecord;
begin
  LDNSRecord := TDNSRecord.Create;
  try
    LDNSRecord.Name := 'txt';
    LDNSRecord.RecordType := drtTXT;
    LDNSRecord.Value := 'hello world';
    LDNSRecord.TTL := 300;
    LCreatedDNSRecord := FClient.CreateRecord(FZoneName, LDNSRecord);
    Assert.IsNotEmpty(LCreatedDNSRecord.Id);

    LCreatedDNSRecord.Value := 'Hello World Updated';
    LCreatedDNSRecord.TTL := 600;

    FClient.UpdateRecord(FZoneName, LCreatedDNSRecord);

    FClient.DeleteRecord(FZoneName, LCreatedDNSRecord.Id);
  finally
    FreeAndNil(LDNSRecord);
    FreeAndNil(LCreatedDNSRecord);
  end;
end;

procedure TDnsProviderTestsBase.Create_Delete_CNAME_Record;
var
  LDNSRecord: TDNSRecord;
  LCreatedDNSRecord: TDNSRecord;
begin
  LDNSRecord := TDNSRecord.Create;
  try
    LDNSRecord.Name := 'alias';
    LDNSRecord.RecordType := drtCNAME;
    LDNSRecord.Value := 'www.tysontechnology.com.au.';
    LDNSRecord.TTL := 300;
    LCreatedDNSRecord := FClient.CreateRecord(FZoneName, LDNSRecord);
    Assert.IsNotNull(LCreatedDNSRecord);
    Assert.IsNotEmpty(LCreatedDNSRecord.Id);

    LCreatedDNSRecord.Name := 'alias';
    LCreatedDNSRecord.TTL := 600;
    LCreatedDNSRecord.Value := 'www.tysontechnology.com.au.';

    FClient.UpdateRecord(FZoneName, LCreatedDNSRecord);

    FClient.DeleteRecord(FZoneName, LCreatedDNSRecord.Id);
  finally
    FreeAndNil(LDNSRecord);
    FreeAndNil(LCreatedDNSRecord);
  end;
end;

procedure TDnsProviderTestsBase.Create_Delete_MX_Record;
var
  LDNSRecord: TDNSRecord;
  LCreatedDNSRecord: TDNSRecord;
begin
  LDNSRecord := TDNSRecord.Create;
  try
    LDNSRecord.Name := '@';
    LDNSRecord.RecordType := drtMX;
    LDNSRecord.Value := 'mail.example.com.';
    LDNSRecord.Priority := 10;
    LDNSRecord.TTL := 300;
    LCreatedDNSRecord := FClient.CreateRecord(FZoneName, LDNSRecord);
    Assert.IsNotNull(LCreatedDNSRecord);
    Assert.IsNotEmpty(LCreatedDNSRecord.Id);

    LCreatedDNSRecord.Value := FZoneName;
    LCreatedDNSRecord.Value := 'mail.example.com.';
    LCreatedDNSRecord.TTL := 600;

    FClient.UpdateRecord(FZoneName, LCreatedDNSRecord);

    FClient.DeleteRecord(FZoneName, LCreatedDNSRecord.Id);
  finally
    FreeAndNil(LDNSRecord);
    FreeAndNil(LCreatedDNSRecord);
  end;
end;

procedure TDnsProviderTestsBase.Create_Delete_AAAA_Record;
var
  LDNSRecord: TDNSRecord;
  LCreatedDNSRecord: TDNSRecord;
begin
//  if not Capabilities.SupportsAAAA then
//    Assert.Ignore('AAAA records not supported by provider');
  LDNSRecord := TDNSRecord.Create;
  try
    LDNSRecord.Name := 'ipv6';
    LDNSRecord.RecordType := drtAAAA;
    LDNSRecord.Value := '2001:db8::1';
  //  LDNSRecord.Priority := 10;
    LDNSRecord.TTL := 300;

    LCreatedDNSRecord := FClient.CreateRecord(FZoneName, LDNSRecord);
    Assert.IsNotNull(LCreatedDNSRecord);

    Assert.IsNotEmpty(LCreatedDNSRecord.Id);

    FClient.UpdateRecord(FZoneName, LCreatedDNSRecord);

    FClient.DeleteRecord(FZoneName, LCreatedDNSRecord.Id);
  finally
    FreeAndNil(LDNSRecord);
    FreeAndNil(LCreatedDNSRecord);
  end;
end;


end.
