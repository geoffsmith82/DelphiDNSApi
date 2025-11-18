unit DNS.UI.Main;

interface

uses
  System.SysUtils,
  System.Types,
  System.UITypes,
  System.Classes,
  System.Variants,
  System.Generics.Collections,
  System.Threading,
  System.StrUtils,
  System.Math,
  FMX.Types,
  FMX.Controls,
  FMX.Forms,
  FMX.Graphics,
  FMX.Dialogs,
  FMX.StdCtrls,
  FMX.Controls.Presentation,
  FMX.Layouts,
  FMX.ListBox,
  FMX.Edit,
  FMX.Objects,
  FMX.TabControl,
  FMX.ListView.Types,
  FMX.ListView.Appearances,
  FMX.ListView.Adapters.Base,
  FMX.ListView,
  FMX.DialogService,
  FMX.Memo,
  FMX.ScrollBox,
  FMX.Ani,
  FMX.Effects,
  DNS.Base,
  DNS.Azure,
  DNS.Bunny,
  DNS.Cloudflare,
  DNS.DigitalOcean,
  DNS.Google,
  DNS.Route53,
  DNS.Vultr,
  DNS.Helpers;

type
  TDNSProviderType = (dpAzure, dpBunny, dpCloudflare, dpDigitalOcean, dpGoogle, dpRoute53, dpVultr);

  TMainForm = class(TForm)
    MainLayout: TLayout;
    HeaderLayout: TLayout;
    ContentLayout: TLayout;

    HeaderRect: TRectangle;
    AppTitle: TLabel;

    TabControl: TTabControl;
    TabZones: TTabItem;
    TabRecords: TTabItem;

    // Zones Tab
    ZonesLayout: TLayout;
    ZonesToolbar: TLayout;
    btnRefreshZones: TButton;
    btnAddZone: TButton;
    btnDeleteZone: TButton;
    ZonesList: TListView;

    // Records Tab
    RecordsLayout: TLayout;
    RecordsToolbar: TLayout;
    CurrentZoneLabel: TLabel;
    btnBackToZones: TButton;
    btnRefreshRecords: TButton;
    btnAddRecord: TButton;
    btnEditRecord: TButton;
    btnDeleteRecord: TButton;
    RecordsList: TListView;
    RecordTypeFilter: TComboBox;
    SearchEdit: TEdit;
    SearchButton: TSpeedButton;

    // Status Bar
    StatusBar: TLayout;
    StatusRect: TRectangle;
    StatusLabel: TLabel;
    ActivityIndicator: TAniIndicator;

    // API Setup Panel
    SetupPanel: TRectangle;
    SetupLayout: TLayout;
    SetupScrollBox: TVertScrollBox;
    SetupTitle: TLabel;
    ProviderLabel: TLabel;
    ProviderComboBox: TComboBox;
    ApiKeyEdit: TEdit;
    AzureLayout: TLayout;
    AzureTenantIdLabel: TLabel;
    AzureTenantIdEdit: TEdit;
    AzureClientIdLabel: TLabel;
    AzureClientIdEdit: TEdit;
    AzureClientSecretLabel: TLabel;
    AzureClientSecretEdit: TEdit;
    AzureSubscriptionLabel: TLabel;
    AzureSubscriptionIdEdit: TEdit;
    AzureResourceGroupLabel: TLabel;
    AzureResourceGroupEdit: TEdit;
    btnSaveApiKey: TButton;
    btnCancelSetup: TButton;

    // Record Edit Panel
    RecordEditPanel: TRectangle;
    RecordEditLayout: TLayout;
    RecordEditScrollBox: TVertScrollBox;
    RecordEditTitle: TLabel;
    edtRecordName: TEdit;
    cmbRecordType: TComboBox;
    edtRecordValue: TEdit;
    edtRecordTTL: TEdit;
    edtRecordPriority: TEdit;
    edtRecordWeight: TEdit;
    edtRecordPort: TEdit;
    edtRecordFlags: TEdit;
    edtRecordTag: TEdit;
    lblRecordName: TLabel;
    lblRecordType: TLabel;
    lblRecordValue: TLabel;
    lblRecordTTL: TLabel;
    lblRecordPriority: TLabel;
    lblRecordWeight: TLabel;
    lblRecordPort: TLabel;
    lblRecordFlags: TLabel;
    lblRecordTag: TLabel;
    btnSaveRecord: TButton;
    btnCancelRecord: TButton;
    RecordEditShadow: TShadowEffect;

    // Add Zone
    ZoneAddPanel: TRectangle;
    ZoneAddLayout: TLayout;
    ZoneAddScrollBox: TVertScrollBox;
    ZoneAddTitle: TLabel;
    edtZoneDomain: TEdit;
    lblZoneDomain: TLabel;
    btnSaveZone: TButton;
    btnCancelZone: TButton;
    ZoneAddShadow: TShadowEffect;

    // Animations
    SlideIn: TFloatAnimation;
    SlideOut: TFloatAnimation;
    FadeIn: TFloatAnimation;
    FadeOut: TFloatAnimation;

    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure btnSaveApiKeyClick(Sender: TObject);
    procedure btnCancelSetupClick(Sender: TObject);
    procedure btnRefreshZonesClick(Sender: TObject);
    procedure btnAddZoneClick(Sender: TObject);
    procedure btnDeleteZoneClick(Sender: TObject);
    procedure btnSaveZoneClick(Sender: TObject);
    procedure btnCancelZoneClick(Sender: TObject);
    procedure ZonesListItemClick(const Sender: TObject; const AItem: TListViewItem);
    procedure btnBackToZonesClick(Sender: TObject);
    procedure btnRefreshRecordsClick(Sender: TObject);
    procedure btnAddRecordClick(Sender: TObject);
    procedure btnEditRecordClick(Sender: TObject);
    procedure btnDeleteRecordClick(Sender: TObject);
    procedure btnSaveRecordClick(Sender: TObject);
    procedure btnCancelRecordClick(Sender: TObject);
    procedure cmbRecordTypeChange(Sender: TObject);
    procedure RecordTypeFilterChange(Sender: TObject);
    procedure SearchButtonClick(Sender: TObject);
    procedure RecordsListItemClick(const Sender: TObject; const AItem: TListViewItem);
    procedure ProviderComboBoxChange(Sender: TObject);
  private
    FProvider: TBaseDNSProvider;
    FCurrentProviderType: TDNSProviderType;
    FCurrentZone: string;
    FZones: TObjectList<TDNSZone>;
    FRecords: TObjectList<TDNSRecord>;
    FEditingRecord: TDNSRecord;
    FSelectedRecordIndex: Integer;

    procedure DoHideSetupPanel(Sender: TObject);
    procedure DoHideZoneAddPanel(Sender: TObject);
    procedure DoHideRecordEditPanel(Sender: TObject);

    procedure InitializeProviders;
    procedure UpdateAuthFieldVisibility;
    function ProviderTypeToName(AType: TDNSProviderType): string;
    function ProviderNameToType(const AName: string): TDNSProviderType;
    function CreateProviderFromCurrentSettings: Boolean;

    procedure LoadApiKey;
    procedure SaveApiKey(const AKey: string);
    procedure ShowSetupPanel;
    procedure HideSetupPanel;
    procedure ShowRecordEditPanel(ARecord: TDNSRecord = nil);
    procedure HideRecordEditPanel;
    procedure ShowZoneAddPanel;
    procedure HideZoneAddPanel;
    procedure LoadZones;
    procedure LoadRecords(const AZone: string);
    procedure UpdateRecordFieldsVisibility;
    procedure SetStatus(const AMessage: string; AShowActivity: Boolean = False);
    procedure ClearStatus;
    procedure ShowError(const AMessage: string);
    procedure InitializeRecordTypes;
    procedure FilterRecords;
    function GetApiKeyPath: string;
    procedure LoadStoredCredentialsForCurrentProvider;

  public
  end;

var
  MainForm: TMainForm;

implementation

uses
  System.IOUtils, System.IniFiles;

{$R *.fmx}

procedure TMainForm.FormCreate(Sender: TObject);
begin
  FZones := TObjectList<TDNSZone>.Create(True);
  FRecords := TObjectList<TDNSRecord>.Create(True);

  FProvider := nil;
  FSelectedRecordIndex := -1;

  InitializeRecordTypes;
  InitializeProviders;

  // Load saved settings but DO NOT activate provider
  LoadApiKey;
end;

procedure TMainForm.FormDestroy(Sender: TObject);
begin
  FProvider.Free;
  FZones.Free;
  FRecords.Free;
end;

function TMainForm.ProviderTypeToName(AType: TDNSProviderType): string;
begin
  case AType of
    dpDigitalOcean: Result := 'DigitalOcean';
    dpVultr:       Result := 'Vultr';
    dpAzure:       Result := 'Azure';
    dpBunny:       Result := 'Bunny.net';
    dpRoute53:     Result := 'AWS Route 53';
    dpGoogle:      Result := 'Google DNS';
    dpCloudflare:  Result := 'Cloudflare';
  else
    Result := 'DigitalOcean';
  end;
end;

function TMainForm.ProviderNameToType(const AName: string): TDNSProviderType;
begin
  if SameText(AName, 'Vultr') then
    Result := dpVultr
  else if SameText(AName, 'Azure') then
    Result := dpAzure
  else if SameText(AName, 'DigitalOcean') then
    Result := dpDigitalOcean
  else if SameText(AName, 'Bunny.net') then
    Result := dpBunny
  else if SameText(AName, 'AWS Route 53') then
    Result := dpRoute53
  else if SameText(AName, 'Google DNS') then
    Result := dpGoogle
  else if SameText(AName, 'Cloudflare') then
    Result := dpCloudflare
  else
    Result := dpDigitalOcean;
end;

procedure TMainForm.InitializeProviders;
begin
  if Assigned(ProviderComboBox) then
  begin
    ProviderComboBox.Items.Clear;
    ProviderComboBox.Items.Add('DigitalOcean');
    ProviderComboBox.Items.Add('Vultr');
    ProviderComboBox.Items.Add('Azure');
    ProviderComboBox.Items.Add('Bunny.net');
    ProviderComboBox.Items.Add('AWS Route 53');
    ProviderComboBox.Items.Add('Google DNS');
    ProviderComboBox.Items.Add('Cloudflare');
    ProviderComboBox.ItemIndex := 0;
  end;

  FCurrentProviderType := dpDigitalOcean;
  UpdateAuthFieldVisibility;
end;

procedure TMainForm.UpdateAuthFieldVisibility;
var
  IsAzure: Boolean;
begin
  IsAzure := FCurrentProviderType = dpAzure;

  // DigitalOcean/Vultr: API key only
  ApiKeyEdit.Visible := not IsAzure;

  AzureLayout.Visible := (FCurrentProviderType = dpAzure);
  AzureLayout.Height :=  AzureResourceGroupEdit.Position.Y + 40;

  // Force FMX to recalc vertical stacking:
//  SetupLayout.Realign;
  SetupScrollBox.RealignContent;


  if FCurrentProviderType = dpDigitalOcean then
    SetupTitle.Text := 'DigitalOcean API Setup'
  else if FCurrentProviderType = dpVultr then
    SetupTitle.Text := 'Vultr API Setup'
  else if FCurrentProviderType = dpBunny then
    SetupTitle.Text := 'Bunny.net Setup'
  else if FCurrentProviderType = dpCloudflare then
    SetupTitle.Text := 'Cloudflare Setup'
  else if FCurrentProviderType = dpGoogle then
    SetupTitle.Text := 'Google Setup'
  else if FCurrentProviderType = dpRoute53 then
    SetupTitle.Text := 'Amazon Route 53 Setup'
  else
    SetupTitle.Text := 'Azure DNS API Setup';

    SetupScrollBox.Height := btnCancelSetup.Position.Y + btnCancelSetup.Height - SetupScrollBox.Position.Y;
    SetupPanel.Height := (SetupScrollBox.Height + 40);

end;

function TMainForm.CreateProviderFromCurrentSettings: Boolean;
begin
  Result := False;
  FreeAndNil(FProvider);

  case FCurrentProviderType of
    dpDigitalOcean:
      FProvider := TDigitalOceanDNSProvider.Create(ApiKeyEdit.Text);

    dpVultr:
      FProvider := TVultrDNSProvider.Create(ApiKeyEdit.Text, '');
    dpBunny:
      FProvider := TBunnyDNSProvider.Create(ApiKeyEdit.Text, '');
    dpCloudflare:
      FProvider := TCloudflareDNSProvider.Create(ApiKeyEdit.Text, '');
    dpGoogle:
      FProvider := TGoogleDNSProvider.Create(ApiKeyEdit.Text, '');
    dpAzure:
      FProvider := TAzureDNSProvider.Create(
        AzureTenantIdEdit.Text,
        AzureClientIdEdit.Text,
        AzureClientSecretEdit.Text,
        AzureSubscriptionIdEdit.Text,
        AzureResourceGroupEdit.Text
      );
  end;

  Result := FProvider <> nil;
end;

function TMainForm.GetApiKeyPath: string;
begin
  Result := TPath.Combine(TPath.GetHomePath, 'digitalocean_dns_config.ini');
end;

procedure TMainForm.LoadApiKey;
var
  Ini: TIniFile;
  ProviderName: string;
begin
  if not FileExists(GetApiKeyPath) then
  begin
    ProviderComboBox.ItemIndex := -1;
    ShowSetupPanel;
    Exit;
  end;

  Ini := TIniFile.Create(GetApiKeyPath);
  try
    ProviderName := Ini.ReadString('General', 'Provider', '');

    // No provider saved → force user to choose
    if ProviderName = '' then
    begin
      ProviderComboBox.ItemIndex := -1;
      ShowSetupPanel;
      Exit;
    end;

    // Set dropdown
    FCurrentProviderType := ProviderNameToType(ProviderName);
    ProviderComboBox.ItemIndex := Ord(FCurrentProviderType);

    // Load saved credentials
    LoadStoredCredentialsForCurrentProvider;

    // Important:
    // We DO NOT create the provider here.
    // We DO NOT load zones here.
    // User must hit Save manually to activate it.

    // Instead, show setup panel so user can confirm or change settings
    ShowSetupPanel;

  finally
    Ini.Free;
  end;
end;



procedure TMainForm.SaveApiKey(const AKey: string);
var
  Ini: TIniFile;
begin
  Ini := TIniFile.Create(GetApiKeyPath);
  try
    Ini.WriteString('General', 'Provider', ProviderTypeToName(FCurrentProviderType));

    case FCurrentProviderType of
      dpRoute53:
        Ini.WriteString('Route53', 'ApiKey', ApiKeyEdit.Text);
      dpCloudflare:
        Ini.WriteString('Cloudflare', 'ApiKey', ApiKeyEdit.Text);
      dpDigitalOcean:
        Ini.WriteString('DigitalOcean', 'ApiKey', ApiKeyEdit.Text);

      dpVultr:
        Ini.WriteString('Vultr', 'ApiKey', ApiKeyEdit.Text);

      dpGoogle:
        Ini.WriteString('Google', 'ApiKey', ApiKeyEdit.Text);
      dpAzure:
        begin
          Ini.WriteString('Azure', 'TenantId',       AzureTenantIdEdit.Text);
          Ini.WriteString('Azure', 'ClientId',       AzureClientIdEdit.Text);
          Ini.WriteString('Azure', 'ClientSecret',   AzureClientSecretEdit.Text);
          Ini.WriteString('Azure', 'SubscriptionId', AzureSubscriptionIdEdit.Text);
          Ini.WriteString('Azure', 'ResourceGroup',  AzureResourceGroupEdit.Text);
        end;
    end;
  finally
    Ini.Free;
  end;
end;

procedure TMainForm.ProviderComboBoxChange(Sender: TObject);
begin
  case ProviderComboBox.ItemIndex of
    0: FCurrentProviderType := dpDigitalOcean;  //DigitalOcean
    1: FCurrentProviderType := dpVultr; // Vultr
    2: FCurrentProviderType := dpAzure; // Azure
    3: FCurrentProviderType := dpBunny; // Bunny.net
    4: FCurrentProviderType := dpRoute53; // AWS Route 53
    5: FCurrentProviderType := dpGoogle; //  Google DNS
    6: FCurrentProviderType := dpCloudflare;//  Cloudflare
  else
    FCurrentProviderType := dpDigitalOcean;
  end;

  UpdateAuthFieldVisibility;
  LoadStoredCredentialsForCurrentProvider;
end;


procedure TMainForm.LoadStoredCredentialsForCurrentProvider;
var
  Ini: TIniFile;
begin
  Ini := TIniFile.Create(GetApiKeyPath);
  try
    case FCurrentProviderType of
      dpBunny:
        ApiKeyEdit.Text := Ini.ReadString('Bunny', 'ApiKey', '');
      dpCloudflare:
        ApiKeyEdit.Text := Ini.ReadString('Cloudeflare', 'ApiKey', '');
      dpRoute53:
        ApiKeyEdit.Text := Ini.ReadString('Route53', 'ApiKey', '');
      dpDigitalOcean:
        ApiKeyEdit.Text := Ini.ReadString('DigitalOcean', 'ApiKey', '');

      dpVultr:
        ApiKeyEdit.Text := Ini.ReadString('Vultr', 'ApiKey', '');

      dpAzure:
      begin
        AzureTenantIdEdit.Text       := Ini.ReadString('Azure', 'TenantId', '');
        AzureClientIdEdit.Text       := Ini.ReadString('Azure', 'ClientId', '');
        AzureClientSecretEdit.Text   := Ini.ReadString('Azure', 'ClientSecret', '');
        AzureSubscriptionIdEdit.Text := Ini.ReadString('Azure', 'SubscriptionId', '');
        AzureResourceGroupEdit.Text  := Ini.ReadString('Azure', 'ResourceGroup', '');
      end;
    end;
  finally
    FreeAndNil(Ini);
  end;
end;


procedure TMainForm.ShowSetupPanel;
begin
  SetupPanel.Position.Y := -SetupPanel.Height;
  SetupPanel.Visible := True;
  SetupPanel.BringToFront;

  SlideIn.Parent := SetupPanel;
  SlideIn.StartValue := -SetupPanel.Height;
  SlideIn.StopValue := (Height - SetupPanel.Height) / 2;
  SlideIn.Start;
end;

procedure TMainForm.DoHideSetupPanel(Sender: TObject);
begin
  SetupPanel.Visible := False;
end;

procedure TMainForm.HideSetupPanel;
begin
  SlideOut.Parent := SetupPanel;
  SlideOut.StartValue := SetupPanel.Position.Y;
  SlideOut.StopValue := -SetupPanel.Height;
  SlideOut.OnFinish := DoHideSetupPanel;
  SlideOut.Start;
end;

procedure TMainForm.btnSaveApiKeyClick(Sender: TObject);
begin
  // Validate fields for the chosen provider
  case FCurrentProviderType of
    dpDigitalOcean, dpVultr:
      if Trim(ApiKeyEdit.Text) = '' then
      begin
        ShowError('Please enter an API key.');
        Exit;
      end;

    dpAzure:
    begin
      if Trim(AzureTenantIdEdit.Text) = '' then
      begin
        ShowError('Enter Azure Tenant ID.');
        Exit;
      end;
      if Trim(AzureClientIdEdit.Text) = '' then
      begin
        ShowError('Enter Azure Client ID.');
        Exit;
      end;
      if Trim(AzureClientSecretEdit.Text) = '' then
      begin
        ShowError('Enter Azure Client Secret.');
        Exit;
      end;
      if Trim(AzureSubscriptionIdEdit.Text) = '' then
      begin
        ShowError('Enter Azure Subscription ID.');
        Exit;
      end;
      if Trim(AzureResourceGroupEdit.Text) = '' then
      begin
        ShowError('Enter Azure Resource Group.');
        Exit;
      end;
    end;
  end;

  // Save credentials to INI
  SaveApiKey('');

  // remove old provider
  FreeAndNil(FProvider);

  // create correct provider
  if not CreateProviderFromCurrentSettings then
  begin
    ShowError('Unable to create provider with current settings');
    Exit;
  end;

  // close setup panel
  HideSetupPanel;

  // Reload zones from the new provider
  LoadZones;
end;


procedure TMainForm.btnCancelSetupClick(Sender: TObject);
begin
  if FProvider = nil then
    Application.Terminate
  else
    HideSetupPanel;
end;

procedure TMainForm.InitializeRecordTypes;
var
  RecType: TDNSRecordType;
begin
  cmbRecordType.Items.Clear;
  RecordTypeFilter.Items.Clear;

  RecordTypeFilter.Items.Add('All Types');

  for RecType := Low(TDNSRecordType) to High(TDNSRecordType) do
  begin
    cmbRecordType.Items.Add(RecType.ToLongString);
    RecordTypeFilter.Items.Add(RecType.ToString);
  end;

  RecordTypeFilter.ItemIndex := 0;
end;

procedure TMainForm.LoadZones;
begin
  if FProvider = nil then Exit;

  SetStatus('Loading zones...', True);

  TTask.Run(
    procedure
    var
      Zones: TObjectList<TDNSZone>;

    begin
      try
        Zones := FProvider.ListZones;
        try
          TThread.Synchronize(nil,
            procedure
            var
              Item: TListViewItem;
            begin
              ZonesList.Items.Clear;
              FZones.Clear;
              var    Zone: TDNSZone;
              for Zone in Zones do
              begin
                Item := ZonesList.Items.Add;
                Item.Text := Zone.Domain;
                Item.Detail := Format('Created: %s',
                  [DateTimeToStr(Zone.CreatedAt)]);
                Item.ButtonText := 'Manage';
                FZones.Add(Zone);
              end;

              ClearStatus;
              SetStatus(Format('Loaded %d zones', [Zones.Count]));
            end);
        finally
        end;
      except
        on E: Exception do
        begin
          TThread.Synchronize(nil,
            procedure
            begin
              ClearStatus;
              ShowError('Failed to load zones: ' + E.Message);
            end);
        end;
      end;
    end);
end;

procedure TMainForm.ShowZoneAddPanel;
begin
  edtZoneDomain.Text := '';
  ZoneAddPanel.Position.Y := -ZoneAddPanel.Height;
  ZoneAddPanel.Visible := True;
  ZoneAddPanel.BringToFront;

  SlideIn.Parent := ZoneAddPanel;
  SlideIn.StartValue := -ZoneAddPanel.Height;
  SlideIn.StopValue := (Height - ZoneAddPanel.Height) / 2;
  SlideIn.Start;

  edtZoneDomain.SetFocus;
end;

procedure TMainForm.DoHideZoneAddPanel(Sender: TObject);
begin
  ZoneAddPanel.Visible := False;
end;

procedure TMainForm.HideZoneAddPanel;
begin
  SlideOut.Parent := ZoneAddPanel;
  SlideOut.StartValue := ZoneAddPanel.Position.Y;
  SlideOut.StopValue := -ZoneAddPanel.Height;
  SlideOut.OnFinish := DoHideZoneAddPanel;
  SlideOut.Start;
end;

procedure TMainForm.btnAddZoneClick(Sender: TObject);
begin
  ShowZoneAddPanel;
end;

procedure TMainForm.btnSaveZoneClick(Sender: TObject);
var
  DomainName: string;
begin
  DomainName := Trim(edtZoneDomain.Text);
  if DomainName = '' then
  begin
    ShowError('Please enter a domain name');
    Exit;
  end;

  SetStatus('Creating zone...', True);
  HideZoneAddPanel;

  TTask.Run(
    procedure
    var
      NewZone: TDNSZone;
    begin
      try
        NewZone := FProvider.CreateZone(DomainName);
        try
          TThread.Synchronize(nil,
            procedure
            begin
              ClearStatus;
              SetStatus('Zone created successfully');
              LoadZones;
            end);
        finally
          NewZone.Free;
        end;
      except
        on E: Exception do
        begin
          TThread.Synchronize(nil,
            procedure
            begin
              ClearStatus;
              ShowError('Failed to create zone: ' + E.Message);
            end);
        end;
      end;
    end);
end;

procedure TMainForm.btnCancelZoneClick(Sender: TObject);
begin
  HideZoneAddPanel;
end;

procedure TMainForm.ZonesListItemClick(const Sender: TObject;
  const AItem: TListViewItem);
begin
  if (AItem <> nil) and (AItem.Index < FZones.Count) then
    LoadRecords(FZones[AItem.Index].Domain);
end;

procedure TMainForm.btnDeleteZoneClick(Sender: TObject);
begin
  if ZonesList.Selected = nil then
  begin
    ShowError('Please select a zone to delete');
    Exit;
  end;

  TDialogService.MessageDialog('Are you sure you want to delete this zone?',
    TMsgDlgType.mtConfirmation, [TMsgDlgBtn.mbYes, TMsgDlgBtn.mbNo],
    TMsgDlgBtn.mbNo, 0,
    procedure(const AResult: TModalResult)
    begin
      if AResult = mrYes then
      begin
        SetStatus('Deleting zone...', True);

        TTask.Run(
          procedure
          var
            ZoneName: string;
          begin
            ZoneName := FZones[ZonesList.Selected.Index].Domain;
            try
              if FProvider.DeleteZone(ZoneName) then
              begin
                TThread.Synchronize(nil,
                  procedure
                  begin
                    ClearStatus;
                    SetStatus('Zone deleted successfully');
                    LoadZones;
                  end);
              end;
            except
              on E: Exception do
              begin
                TThread.Synchronize(nil,
                  procedure
                  begin
                    ClearStatus;
                    ShowError('Failed to delete zone: ' + E.Message);
                  end);
              end;
            end;
          end);
      end;
    end);
end;

procedure TMainForm.btnBackToZonesClick(Sender: TObject);
begin
  TabControl.ActiveTab := TabZones;
end;

procedure TMainForm.LoadRecords(const AZone: string);
begin
  if FProvider = nil then Exit;

  FCurrentZone := AZone;
  CurrentZoneLabel.Text := 'Zone: ' + AZone;
  SetStatus('Loading records for ' + AZone + '...', True);

  TTask.Run(
    procedure
    var
      Records: TObjectList<TDNSRecord>;

    begin
      try
        Records := FProvider.ListRecords(AZone);
        try
          TThread.Synchronize(nil,
            procedure
            var
              Item: TListViewItem;
            begin
              RecordsList.Items.Clear;
              FRecords.Clear;
              var Rec: TDNSRecord;
              for Rec in Records do
              begin
                Item := RecordsList.Items.Add;
                Item.Text := Format('%s %s.%s',
                  [Rec.RecordType.ToString, Rec.Name, AZone]);
                Item.Detail := Format('Value: %s | TTL: %d',
                  [Rec.Value, Rec.TTL]);
                Item.TagObject := Rec;
                FRecords.Add(Rec);
              end;

              TabControl.ActiveTab := TabRecords;
              ClearStatus;
              SetStatus(Format('Loaded %d records', [Records.Count]));
            end);
        finally
        end;
      except
        on E: Exception do
        begin
          TThread.Synchronize(nil,
            procedure
            begin
              ClearStatus;
              ShowError('Failed to load records: ' + E.Message);
            end);
        end;
      end;
    end);
end;

procedure TMainForm.btnRefreshRecordsClick(Sender: TObject);
begin
  if FCurrentZone <> '' then
    LoadRecords(FCurrentZone);
end;

procedure TMainForm.btnRefreshZonesClick(Sender: TObject);
begin
  LoadZones;
end;

procedure TMainForm.btnAddRecordClick(Sender: TObject);
begin
  ShowRecordEditPanel(nil);
end;

procedure TMainForm.btnEditRecordClick(Sender: TObject);
begin
  if RecordsList.Selected = nil then
  begin
    ShowError('Please select a record to edit');
    Exit;
  end;

  if RecordsList.Selected.Index < FRecords.Count then
    ShowRecordEditPanel(FRecords[RecordsList.Selected.Index]);
end;

procedure TMainForm.btnDeleteRecordClick(Sender: TObject);
begin
  if RecordsList.Selected = nil then
  begin
    ShowError('Please select a record to delete');
    Exit;
  end;

  TDialogService.MessageDialog('Are you sure you want to delete this record?',
    TMsgDlgType.mtConfirmation, [TMsgDlgBtn.mbYes, TMsgDlgBtn.mbNo],
    TMsgDlgBtn.mbNo, 0,
    procedure(const AResult: TModalResult)
    begin
      if AResult = mrYes then
      begin
        SetStatus('Deleting record...', True);

        TTask.Run(
          procedure
          var
            RecordId: string;
          begin
            RecordId := FRecords[RecordsList.Selected.Index].Id;
            try
              if FProvider.DeleteRecord(FCurrentZone, RecordId) then
              begin
                TThread.Synchronize(nil,
                  procedure
                  begin
                    ClearStatus;
                    SetStatus('Record deleted successfully');
                    LoadRecords(FCurrentZone);
                  end);
              end;
            except
              on E: Exception do
              begin
                TThread.Synchronize(nil,
                  procedure
                  begin
                    ClearStatus;
                    ShowError('Failed to delete record: ' + E.Message);
                  end);
              end;
            end;
          end);
      end;
    end);
end;

procedure TMainForm.ShowRecordEditPanel(ARecord: TDNSRecord);
begin
  FEditingRecord := ARecord;

  if ARecord = nil then
  begin
    RecordEditTitle.Text := 'Add New Record';
    edtRecordName.Text := '';
    cmbRecordType.ItemIndex := 0;
    edtRecordValue.Text := '';
    edtRecordTTL.Text := '3600';
    edtRecordPriority.Text := '10';
    edtRecordWeight.Text := '0';
    edtRecordPort.Text := '0';
    edtRecordFlags.Text := '0';
    edtRecordTag.Text := '';
  end
  else
  begin
    RecordEditTitle.Text := 'Edit Record';
    edtRecordName.Text := ARecord.Name;
    cmbRecordType.ItemIndex := Ord(ARecord.RecordType);
    edtRecordValue.Text := ARecord.Value;
    edtRecordTTL.Text := IntToStr(ARecord.TTL);
    edtRecordPriority.Text := IntToStr(ARecord.Priority);
    edtRecordWeight.Text := IntToStr(ARecord.Weight);
    edtRecordPort.Text := IntToStr(ARecord.Port);
    edtRecordFlags.Text := IntToStr(ARecord.Flags);
    edtRecordTag.Text := ARecord.Tag;
  end;

  UpdateRecordFieldsVisibility;

  RecordEditPanel.Position.Y := -RecordEditPanel.Height;
  RecordEditPanel.Visible := True;
  RecordEditPanel.BringToFront;

  SlideIn.Parent := RecordEditPanel;
  SlideIn.StartValue := -RecordEditPanel.Height;
  SlideIn.StopValue := (Height - RecordEditPanel.Height) / 2;
  SlideIn.Start;
end;

procedure TMainForm.DoHideRecordEditPanel(Sender: TObject);
begin
  RecordEditPanel.Visible := False;
end;

procedure TMainForm.HideRecordEditPanel;
begin
  SlideOut.Parent := RecordEditPanel;
  SlideOut.StartValue := RecordEditPanel.Position.Y;
  SlideOut.StopValue := -RecordEditPanel.Height;
  SlideOut.OnFinish := DoHideRecordEditPanel;
  SlideOut.Start;
end;

procedure TMainForm.cmbRecordTypeChange(Sender: TObject);
begin
  UpdateRecordFieldsVisibility;
end;

procedure TMainForm.UpdateRecordFieldsVisibility;
var
  RecType: TDNSRecordType;
begin
  if cmbRecordType.ItemIndex >= 0 then
  begin
    RecType := TDNSRecordType(cmbRecordType.ItemIndex);

    lblRecordPriority.Visible := RecType.RequiresPriority;
    edtRecordPriority.Visible := RecType.RequiresPriority;

    lblRecordWeight.Visible := RecType.RequiresWeight;
    edtRecordWeight.Visible := RecType.RequiresWeight;
    lblRecordPort.Visible := RecType.RequiresPort;
    edtRecordPort.Visible := RecType.RequiresPort;

    lblRecordFlags.Visible := RecType.RequiresFlags;
    edtRecordFlags.Visible := RecType.RequiresFlags;
    lblRecordTag.Visible := RecType.RequiresTag;
    edtRecordTag.Visible := RecType.RequiresTag;

    edtRecordValue.TextPrompt := RecType.GetExampleValue;

    RecordEditLayout.Height := btnCancelRecord.Position.Y + btnCancelRecord.Height + 10;
    RecordEditPanel.Height := Min(577, RecordEditLayout.Height + 40);
  end;
end;

procedure TMainForm.btnSaveRecordClick(Sender: TObject);
var
  NewRecord: TDNSRecord;
  IsNew: Boolean;
begin
  NewRecord := TDNSRecord.Create;
  try
    IsNew := FEditingRecord = nil;

    if not IsNew then
      NewRecord.Id := FEditingRecord.Id;

    NewRecord.Name := Trim(edtRecordName.Text);
    NewRecord.RecordType := TDNSRecordType(cmbRecordType.ItemIndex);
    NewRecord.Value := Trim(edtRecordValue.Text);
    NewRecord.TTL := StrToIntDef(edtRecordTTL.Text, 3600);
    NewRecord.Priority := StrToIntDef(edtRecordPriority.Text, 10);
    NewRecord.Weight := StrToIntDef(edtRecordWeight.Text, 0);
    NewRecord.Port := StrToIntDef(edtRecordPort.Text, 0);
    NewRecord.Flags := StrToIntDef(edtRecordFlags.Text, 0);
    NewRecord.Tag := Trim(edtRecordTag.Text);

    if not NewRecord.RecordType.ValidateValue(NewRecord.Value) then
    begin
      ShowError('Invalid value for record type ' + NewRecord.RecordType.ToString);
      Exit;
    end;

    SetStatus('Saving record...', True);
    HideRecordEditPanel;

    TTask.Run(
      procedure
      var
        Success: Boolean;
        ResultRecord: TDNSRecord;
      begin
        try
          if IsNew then
          begin
            ResultRecord := FProvider.CreateRecord(FCurrentZone, NewRecord);
            ResultRecord.Free;
            Success := True;
          end
          else
            Success := FProvider.UpdateRecord(FCurrentZone, NewRecord);

          if Success then
          begin
            TThread.Synchronize(nil,
              procedure
              begin
                ClearStatus;
                if IsNew then
                  SetStatus('Record created successfully')
                else
                  SetStatus('Record updated successfully');
                LoadRecords(FCurrentZone);
              end);
          end;
        except
          on E: Exception do
          begin
            TThread.Synchronize(nil,
              procedure
              begin
                ClearStatus;
                ShowError('Failed to save record: ' + E.Message);
              end);
          end;
        end;
      end);
  finally
    NewRecord.Free;
  end;
end;

procedure TMainForm.btnCancelRecordClick(Sender: TObject);
begin
  HideRecordEditPanel;
end;

procedure TMainForm.RecordTypeFilterChange(Sender: TObject);
begin
  FilterRecords;
end;

procedure TMainForm.SearchButtonClick(Sender: TObject);
begin
  FilterRecords;
end;

procedure TMainForm.FilterRecords;
var
  SearchText: string;
  FilterType: TDNSRecordType;
  HasFilter: Boolean;
  Item: TListViewItem;
  Rec: TDNSRecord;
  I: Integer;
begin
  SearchText := LowerCase(Trim(SearchEdit.Text));
  HasFilter := RecordTypeFilter.ItemIndex > 0;

  if HasFilter then
    FilterType := TDNSRecordType(RecordTypeFilter.ItemIndex - 1);

  RecordsList.Items.Clear;

  for I := 0 to FRecords.Count - 1 do
  begin
    Rec := FRecords[I];

    if HasFilter and (Rec.RecordType <> FilterType) then
      Continue;

    if (SearchText <> '') and
       (not ContainsText(LowerCase(Rec.Name), SearchText)) and
       (not ContainsText(LowerCase(Rec.Value), SearchText)) then
      Continue;

    Item := RecordsList.Items.Add;
    Item.Text := Format('%s %s.%s',
      [Rec.RecordType.ToString, Rec.Name, FCurrentZone]);
    Item.Detail := Format('Value: %s | TTL: %d',
      [Rec.Value, Rec.TTL]);
    Item.TagObject := Rec;
  end;
end;

procedure TMainForm.RecordsListItemClick(const Sender: TObject;
  const AItem: TListViewItem);
begin
  FSelectedRecordIndex := AItem.Index;
end;

procedure TMainForm.SetStatus(const AMessage: string; AShowActivity: Boolean);
begin
  StatusLabel.Text := AMessage;
  ActivityIndicator.Visible := AShowActivity;
  ActivityIndicator.Enabled := AShowActivity;
end;

procedure TMainForm.ClearStatus;
begin
  ActivityIndicator.Visible := False;
  ActivityIndicator.Enabled := False;

  TThread.CreateAnonymousThread(
    procedure
    begin
      Sleep(3000);
      TThread.Synchronize(nil,
        procedure
        begin
          StatusLabel.Text := '';
        end);
    end).Start;
end;

procedure TMainForm.ShowError(const AMessage: string);
begin
  TDialogService.ShowMessage(AMessage);
  SetStatus('Error: ' + AMessage);
end;

end.
