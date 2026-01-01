unit ACME.Client;

interface

uses
  System.SysUtils,
  System.Classes,
  System.StrUtils,
  System.DateUtils,
  System.Generics.Collections,
  System.Net.HttpClient,
  System.Net.URLClient,
  System.JSON,
  FMX.Types,
  ACME.Client.Types,
  ACME.TaurusCrypto;

type
  EAcmeClientError = class(Exception);

  TAcmeClient = class
  private
    FHttp        : THTTPClient;
    FDirectoryUrl: string;
    FDirectory   : TAcmeDirectory;
    FSolvers     : TList<IAcmeChallengeSolver>;

    FAccountKey  : TAcmeKeyPair;
    FAccountUrl  : string;  // account URL (kid)
    FAccountFile : string;

    FDnsProviderName: string;

    FCertKey: TAcmeKeyPair;

    procedure LoadDirectory;
    function NewNonce: string;

    function RawPost(const Url, JwsBody: string; out Location: string): TJSONObject;
    function JwsPost(const Url: string; Payload: TJSONValue; UseKid: Boolean; out Location: string): TJSONObject;

    function StatusFromStr(const S: string): TAcmeAuthorizationStatus;
    function GetAuthorizationsForOrder(const OrderObj: TJSONObject): TArray<TAcmeAuthorization>;
    function GetChallengeForAuth(const Auth: TAcmeAuthorization; PrefType: TChallengeType; out Chall: TAcmeChallenge): Boolean;

    function ComputeKeyAuthorization(const Token: string): string;
    procedure ValidateAuthorizations(const OrderObj: TJSONObject; PrefType: TChallengeType; const OrderUrl: string);

    function DownloadCertPem(const CertUrl: string): string;
  private
    FStorageRoot: string;
    function GetStorageRoot: string;
    function GetLiveDir(const Name: string): string;
    function GetArchiveDir(const Name: string): string;
    function GetRenewalFile(const Name: string): string;
    function NextArchiveIndex(const Name: string): Integer;
    procedure EnsureDir(const Path: string);
    procedure WritePemFile(const FileName, Contents: string);
    procedure UpdateLiveCertificate(const Name: string; Version: Integer);
    procedure SaveCertificateSet(const Domains: TArray<string>; const CertPem,
      ChainPem, PrivateKeyPem, DirectoryUrl, AuthMethod, DnsProvider: string);
  public
    constructor Create(const ADirectoryUrl: string = 'https://acme-v02.api.letsencrypt.org/directory');
    destructor Destroy; override;
 
    procedure AddSolver(const Solver: IAcmeChallengeSolver);
 
    procedure RegisterOrLoadAccount(const Email: string; const AccountFile: string);
 
    // High-level: obtain cert + key & full chain as PEM
    procedure ObtainCertificate(const Domains: TArray<string>; const Email: string;
      out CertificatePem, PrivateKeyPem, ChainPem: string;
      PrefType: TChallengeType = ctDns01;
      UseStaging: Boolean = True);
 
    function ComputeDns01TxtValue(const Token: string): string;
 
    // Optional overrides (useful for a certbot-like CLI)
    property StorageRoot: string read FStorageRoot write FStorageRoot;
    property AccountFile: string read FAccountFile write FAccountFile;
    property DnsProviderName: string read FDnsProviderName write FDnsProviderName;
  end;

implementation

uses
  System.Hash,
  System.NetEncoding,
  System.Math,
  System.IOUtils;

{ TAcmeClient *****************************************************************}

function StringToChallengeType(str:string): TChallengeType;
begin
  if str.Contains('http01') then
    Result := ctHttp01
  else
    Result := ctDns01;
end;

function ChallengeTypeToString(challengeType:TChallengeType):String ;
begin
  if challengeType = ctHttp01 then
    Result := 'Http01'
  else
    Result := 'Dns01';
end;


constructor TAcmeClient.Create(const ADirectoryUrl: string);
begin
  inherited Create;
  FHttp := THTTPClient.Create;
  FDirectoryUrl := ADirectoryUrl;
  FSolvers := TList<IAcmeChallengeSolver>.Create;
  LoadDirectory;
end;

destructor TAcmeClient.Destroy;
begin
  FreeAndNil(FAccountKey);
  FreeAndNil(FSolvers);
  FreeAndNil(FHttp);
  inherited;
end;

procedure TAcmeClient.AddSolver(const Solver: IAcmeChallengeSolver);
begin
  FSolvers.Add(Solver);
end;

procedure TAcmeClient.LoadDirectory;
var
  Resp: IHTTPResponse;
  Obj: TJSONObject;
begin
  Resp := FHttp.Get(FDirectoryUrl);
  if (Resp.StatusCode div 100) <> 2 then
    raise EAcmeClientError.CreateFmt('Directory GET failed: %d %s',
      [Resp.StatusCode, Resp.StatusText]);

  Obj := TJSONObject.ParseJSONValue(Resp.ContentAsString) as TJSONObject;
  try
    FDirectory.NewNonceUrl   := Obj.GetValue<string>('newNonce');
    FDirectory.NewAccountUrl := Obj.GetValue<string>('newAccount');
    FDirectory.NewOrderUrl   := Obj.GetValue<string>('newOrder');
  finally
    FreeAndNil(Obj);
  end;
end;


function TAcmeClient.ComputeDns01TxtValue(const Token: string): string;
var
  KeyAuth: string;
  Thumb: string;
  Hash: TBytes;
begin
  if FAccountKey = nil then
    raise EAcmeClientError.Create('ComputeDns01TxtValue: account key not initialized');

  // 1. JWK thumbprint
  Thumb := FAccountKey.ComputeJwkThumbprint;

  // 2. keyAuthorization string
  KeyAuth := Token + '.' + Thumb;

  // 3. SHA-256 hash of keyAuthorization (UTF-8 bytes)
  Hash := THashSHA2.GetHashBytes(KeyAuth);

  // 4. Base64Url encode result
  Result := Base64UrlEncode(Hash);
end;

function TAcmeClient.NewNonce: string;
var
  Resp: IHTTPResponse;
begin
  Resp := FHttp.Head(FDirectory.NewNonceUrl);
  if (Resp.StatusCode div 100) <> 2 then
    raise EAcmeClientError.CreateFmt('newNonce failed: %d %s',
      [Resp.StatusCode, Resp.StatusText]);
  Result := Resp.HeaderValue['Replay-Nonce'];
end;

function TAcmeClient.RawPost(const Url, JwsBody: string; out Location: string): TJSONObject;
var
  Resp: IHTTPResponse;
  Content: TStringStream;
  Headers: TNetHeaders;
begin
  Location := '';

  SetLength(Headers, 1);
  Headers[0].Name  := 'Content-Type';
  Headers[0].Value := 'application/jose+json';

  Content := TStringStream.Create(JwsBody, TEncoding.UTF8);
  try
    Resp := FHttp.Post(Url, Content, nil, Headers);
  finally
    FreeAndNil(Content);
  end;

  if Resp = nil then
    raise EAcmeClientError.Create('HTTP POST returned nil response');

  Location := Resp.HeaderValue['Location'];

  if (Resp.StatusCode < 200) or (Resp.StatusCode >= 300) then
    raise EAcmeClientError.CreateFmt(
      'POST %s failed: %d %s%s%s',
      [Url, Resp.StatusCode, Resp.StatusText, sLineBreak, Resp.ContentAsString]
    );

  if Resp.ContentLength = 0 then
    Exit(nil);

  Result := TJSONObject.ParseJSONValue(Resp.ContentAsString) as TJSONObject;
end;


function TAcmeClient.JwsPost(const Url: string; Payload: TJSONValue;
  UseKid: Boolean; out Location: string): TJSONObject;
var
  Nonce: string;
  HeaderObj: TJSONObject;
  ProtectedHdr, ProtectedB64: string;
  PayloadStr, PayloadB64: string;
  SignatureB64: string;
  BodyObj: TJSONObject;
begin
  Nonce := NewNonce;

  HeaderObj := TJSONObject.Create;
  try
    if FAccountKey = nil then
      raise EAcmeClientError.Create('Account key not initialised (TAcmeKeyPair.GenerateRsa2048 must be implemented)');

    if FAccountKey.KeyType = akRsa2048 then
      HeaderObj.AddPair('alg', 'RS256')
    else
      HeaderObj.AddPair('alg', 'ES256');

    HeaderObj.AddPair('nonce', Nonce);
    HeaderObj.AddPair('url', Url);

    if UseKid then
    begin
      if FAccountUrl = '' then
        raise EAcmeClientError.Create('Account Url is empty – RegisterOrLoadAccount must complete successfully');
      HeaderObj.AddPair('kid', FAccountUrl);
    end
    else
    begin
      // JWK-based header for newAccount
      HeaderObj.AddPair('jwk', FAccountKey.BuildJwk); // BuildJwk must be implemented in TaurusTLS layer
    end;

    ProtectedHdr := HeaderObj.ToJSON;
  finally
    FreeAndNil(HeaderObj);
  end;

  ProtectedB64 := Base64UrlEncodeStr(ProtectedHdr);

  if Assigned(Payload) then
    PayloadStr := Payload.ToJSON
  else
    PayloadStr := ''; // POST-as-GET

  PayloadB64 := Base64UrlEncodeStr(PayloadStr);

  SignatureB64 := FAccountKey.SignJws(ProtectedB64, PayloadB64);

  BodyObj := TJSONObject.Create;
  try
    BodyObj.AddPair('protected', ProtectedB64);
    BodyObj.AddPair('payload', PayloadB64);
    BodyObj.AddPair('signature', SignatureB64);

    Result := RawPost(Url, BodyObj.ToJSON, Location);
  finally
    FreeAndNil(BodyObj);
  end;
end;

function TAcmeClient.StatusFromStr(const S: string): TAcmeAuthorizationStatus;
begin
  if SameText(S, 'valid') then
    Result := asValid
  else if SameText(S, 'pending') then
    Result := asPending
  else
    Result := asInvalid;
end;

function TAcmeClient.GetAuthorizationsForOrder(
  const OrderObj: TJSONObject): TArray<TAcmeAuthorization>;
var
  AuthUrls: TJSONArray;
  Auths: TList<TAcmeAuthorization>;
  I: Integer;
  Url: string;
  Resp: IHTTPResponse;
  AuthObj, IdentObj: TJSONObject;
  ChallArr: TJSONArray;
  J: Integer;
  A: TAcmeAuthorization;
  C: TAcmeChallenge;
  ChallObj: TJSONObject;
begin
  AuthUrls := OrderObj.GetValue('authorizations') as TJSONArray;
  if AuthUrls = nil then
    Exit(nil);

  Auths := TList<TAcmeAuthorization>.Create;
  try
    for I := 0 to AuthUrls.Count - 1 do
    begin
      Url := AuthUrls.Items[I].Value;
      Resp := FHttp.Get(Url);
      if (Resp.StatusCode div 100) <> 2 then
        raise EAcmeClientError.CreateFmt('Get auth failed: %d %s',
          [Resp.StatusCode, Resp.StatusText]);

      AuthObj := TJSONObject.ParseJSONValue(Resp.ContentAsString) as TJSONObject;
      try
        IdentObj := AuthObj.GetValue('identifier') as TJSONObject;
        A.Identifier := IdentObj.GetValue<string>('value');
        A.Status := StatusFromStr(AuthObj.GetValue<string>('status'));
        Log.d(AuthObj.GetValue<string>('status'));

        ChallArr := AuthObj.GetValue('challenges') as TJSONArray;
        SetLength(A.Challenges, ChallArr.Count);
        for J := 0 to ChallArr.Count - 1 do
        begin
          ChallObj := ChallArr.Items[J] as TJSONObject;
          C.ChallengeType := StringToChallengeType(ChallObj.GetValue<string>('type'));
          C.Url           := ChallObj.GetValue<string>('url');
          C.Token         := ChallObj.GetValue<string>('token');
          A.Challenges[J] := C;
        end;

        Auths.Add(A);
      finally
        FreeAndNil(AuthObj);
      end;
    end;

    Result := Auths.ToArray;
  finally
    FreeAndNil(Auths);
  end;
end;

function TAcmeClient.GetChallengeForAuth(const Auth: TAcmeAuthorization;
  PrefType: TChallengeType; out Chall: TAcmeChallenge): Boolean;
var
  I: Integer;
begin
  // First try preferred type
  for I := 0 to Length(Auth.Challenges) - 1 do
    if Auth.Challenges[I].ChallengeType = PrefType then
    begin
      Chall := Auth.Challenges[I];
      Exit(True);
    end;

  // Fallback to first available challenge
  if Length(Auth.Challenges) > 0 then
  begin
    Chall := Auth.Challenges[0];
    Exit(True);
  end;

  Result := False;
end;

function TAcmeClient.ComputeKeyAuthorization(const Token: string): string;
begin
  if FAccountKey = nil then
    raise EAcmeClientError.Create('Account key not initialised');
  Result := Token + '.' + FAccountKey.ComputeJwkThumbprint;
end;

procedure TAcmeClient.ValidateAuthorizations(const OrderObj: TJSONObject;
  PrefType: TChallengeType; const OrderUrl: string);
var
  Auths: TArray<TAcmeAuthorization>;
  Auth: TAcmeAuthorization;
  Chall: TAcmeChallenge;
  Solver: IAcmeChallengeSolver;
  KeyAuth: string;
  ValueForSolver: string;
  Payload: TJSONObject;
  Resp: TJSONObject;
  AllValid: Boolean;
  Attempt: Integer;
begin
  Auths := GetAuthorizationsForOrder(OrderObj);

  // --- 1. For each authorization, choose challenge + present proof ---
  for Auth in Auths do
  begin
    if not GetChallengeForAuth(Auth, PrefType, Chall) then
      raise EAcmeClientError.CreateFmt('No suitable challenge for %s', [Auth.Identifier]);

    // Find matching solver
    Solver := nil;
    for Solver in FSolvers do
      if Solver.CanSolve(Chall.ChallengeType) then
        Break;

    if Solver = nil then
      raise EAcmeClientError.CreateFmt('No solver for challenge type %s', [ChallengeTypeToString(Chall.ChallengeType)]);

    // Compute keyAuthorization (always needed)
    KeyAuth := ComputeKeyAuthorization(Chall.Token);

    // Compute solver-specific value
    case Chall.ChallengeType of
      ctHTTP01:
        ValueForSolver := KeyAuth;

      ctDNS01:
        ValueForSolver := ComputeDns01TxtValue(Chall.Token);

    else
      raise EAcmeClientError.Create('Unsupported challenge type');
    end;

    // Tell solver to install challenge proof (TXT record or HTTP file)
    Solver.Solve(Auth.Identifier, Chall, ValueForSolver);

    // Notify ACME server that challenge is ready
    Payload := TJSONObject.Create;
    try
      var tmp: string;
      Resp := JwsPost(Chall.Url, Payload, True, tmp);
    finally
      FreeAndNil(Payload);
      FreeAndNil(Resp);
    end;
  end;

  // --- 2. Poll all authorizations until they become valid ---
  for Attempt := 1 to 30 do
  begin
    Sleep(2000);
    Auths := GetAuthorizationsForOrder(OrderObj);

    AllValid := True;
    for Auth in Auths do
    begin
      if Auth.Status <> asValid then
      begin
        AllValid := False;
        Break;
      end;
    end;

    if AllValid then
      Break;
  end;

  if not AllValid then
    raise EAcmeClientError.Create('Authorization validation timeout');

  // --- 3. Clean up the challenge proof ---
  for Auth in Auths do
    if GetChallengeForAuth(Auth, PrefType, Chall) then
      for Solver in FSolvers do
        if Solver.CanSolve(Chall.ChallengeType) then
          Solver.Cleanup(Auth.Identifier, Chall);
end;

procedure TAcmeClient.RegisterOrLoadAccount(const Email: string; const AccountFile: string);
var
  Json: TJSONObject;
  S: TStringList;
  KeyPem: string;
  AccountUrl: string;
  Payload: TJSONObject;
  Resp: TJSONObject;
  Location: string;
begin
  // ==============================================================
  // 1. Load existing account if file exists
  // ==============================================================

  if FileExists(AccountFile) then
  begin
    S := TStringList.Create;
    try
      S.LoadFromFile(AccountFile);
      Json := TJSONObject.ParseJSONValue(S.Text) as TJSONObject;
      if Json = nil then
        raise EAcmeClientError.Create('Invalid account file JSON');

      try
        AccountUrl := Json.GetValue<string>('AccountUrl');
        KeyPem     := Json.GetValue<string>('PrivateKeyPem');
      finally
        FreeAndNil(Json);
      end;
    finally
      FreeAndNil(S);
    end;

    // Restore RSA key from PEM
    FAccountKey := TAcmeKeyPair.LoadKeyFromPem(KeyPem);
    FAccountUrl := AccountUrl;

    Exit; // fully loaded; ready for ACME use
  end;

  // ==============================================================
  // 2. No existing account → Register new one
  // ==============================================================

  // Generate RSA-2048 account key
  FAccountKey := TAcmeKeyPair.GenerateRsa2048;

  // Prepare ACME newAccount payload
  Payload := TJSONObject.Create;
  try
    Payload.AddPair('termsOfServiceAgreed', TJSONBool.Create(True));
    if Email <> '' then
      Payload.AddPair('contact',
        TJSONArray.Create(TJSONString.Create('mailto:' + Email)));

    Resp := JwsPost(FDirectory.NewAccountUrl, Payload, {UseKid=} False, Location);
  finally
    FreeAndNil(Payload);
  end;

  try
    // ACME returns the account URL (kid) in Location header
    if Location = '' then
      raise EAcmeClientError.Create('newAccount: missing Location header');

    FAccountUrl := Location;
  finally
    FreeAndNil(Resp);
  end;

  // ==============================================================
  // 3. Save account to disk
  // ==============================================================

  Json := TJSONObject.Create;
  try
    KeyPem := FAccountKey.ExportPrivateKeyPem;

    Json.AddPair('AccountUrl', FAccountUrl);
    Json.AddPair('PrivateKeyPem', KeyPem);

    S := TStringList.Create;
    try
      S.Text := Json.ToJSON;
      S.SaveToFile(AccountFile, TEncoding.UTF8);
    finally
      FreeAndNil(S);
    end;
  finally
    FreeAndNil(Json);
  end;
end;

function TAcmeClient.GetStorageRoot: string;
begin
  if FStorageRoot <> '' then
    Exit(FStorageRoot);

  {$IFDEF MSWINDOWS}
    Result := TPath.Combine(TPath.GetPublicPath, 'AcmeClient');
  {$ELSE}
    Result := '/etc/acme-client';
  {$ENDIF}
end;

function TAcmeClient.GetLiveDir(const Name: string): string;
begin
  Result := TPath.Combine(GetStorageRoot, TPath.Combine('live', Name));
end;

function TAcmeClient.GetArchiveDir(const Name: string): string;
begin
  Result := TPath.Combine(GetStorageRoot, TPath.Combine('archive', Name));
end;

function TAcmeClient.GetRenewalFile(const Name: string): string;
begin
  Result := TPath.Combine(GetStorageRoot, TPath.Combine('renewal', Name + '.json'));
end;

function TAcmeClient.NextArchiveIndex(const Name: string): Integer;
var
  Archive: string;
  Files: TArray<string>;
  MaxIndex, I, N: Integer;
  Base, Ext: string;
begin
  Archive := GetArchiveDir(Name);
  EnsureDir(Archive);

  Files := TDirectory.GetFiles(Archive, 'fullchain*.pem');
  MaxIndex := 0;

  for I := 0 to High(Files) do
  begin
    Base := TPath.GetFileNameWithoutExtension(Files[I]); // fullchain3
    if TryStrToInt(Base.Replace('fullchain', ''), N) then
      if N > MaxIndex then
        MaxIndex := N;
  end;

  Result := MaxIndex + 1;
end;

procedure TAcmeClient.WritePemFile(const FileName, Contents: string);
begin
  EnsureDir(TPath.GetDirectoryName(FileName));
  TFile.WriteAllText(FileName, Contents, TEncoding.UTF8);
end;

procedure TAcmeClient.UpdateLiveCertificate(const Name: string; Version: Integer);
var
  Live, Archive: string;
{$IFDEF MSWINDOWS}
  CertSrc, ChainSrc, FullSrc, KeySrc: string;
{$ELSE}
  function RelPath(const Target: string): string;
  begin
    Result := '../../archive/' + Name + '/' + ExtractFileName(Target);
  end;
{$ENDIF}
begin
  Live := GetLiveDir(Name);
  Archive := GetArchiveDir(Name);

  EnsureDir(Live);

{$IFDEF MSWINDOWS}
  CertSrc  := TPath.Combine(Archive, Format('cert%d.pem', [Version]));
  ChainSrc := TPath.Combine(Archive, Format('chain%d.pem', [Version]));
  FullSrc  := TPath.Combine(Archive, Format('fullchain%d.pem', [Version]));
  KeySrc   := TPath.Combine(Archive, Format('privkey%d.pem', [Version]));

  TFile.Copy(CertSrc,  TPath.Combine(Live, 'cert.pem'), True);
  TFile.Copy(ChainSrc, TPath.Combine(Live, 'chain.pem'), True);
  TFile.Copy(FullSrc,  TPath.Combine(Live, 'fullchain.pem'), True);
  TFile.Copy(KeySrc,   TPath.Combine(Live, 'privkey.pem'), True);

{$ELSE}
  // Linux/macOS: use symlinks
  fpSymlink(PAnsiChar(AnsiString(RelPath(CertSrc))),  PAnsiChar(AnsiString(TPath.Combine(Live, 'cert.pem'))));
  fpSymlink(PAnsiChar(AnsiString(RelPath(ChainSrc))), PAnsiChar(AnsiString(TPath.Combine(Live, 'chain.pem'))));
  fpSymlink(PAnsiChar(AnsiString(RelPath(FullSrc))),  PAnsiChar(AnsiString(TPath.Combine(Live, 'fullchain.pem'))));
  fpSymlink(PAnsiChar(AnsiString(RelPath(KeySrc))),   PAnsiChar(AnsiString(TPath.Combine(Live, 'privkey.pem'))));
{$ENDIF}
end;


function TAcmeClient.DownloadCertPem(const CertUrl: string): string;
var
  Resp: IHTTPResponse;
begin
  Resp := FHttp.Get(CertUrl);
  if (Resp.StatusCode div 100) <> 2 then
    raise EAcmeClientError.CreateFmt('Certificate download failed: %d %s',
      [Resp.StatusCode, Resp.StatusText]);
  Result := Resp.ContentAsString(TEncoding.ASCII);
end;

procedure TAcmeClient.EnsureDir(const Path: string);
begin
  if not DirectoryExists(Path) then
    ForceDirectories(Path);
end;

procedure TAcmeClient.ObtainCertificate(const Domains: TArray<string>;
  const Email: string; out CertificatePem, PrivateKeyPem, ChainPem: string;
  PrefType: TChallengeType; UseStaging: Boolean);
var
  Payload: TJSONObject;
  IdArr: TJSONArray;
  IdentObj: TJSONObject;
  I: Integer;
  Resp, OrderObj: TJSONObject;
  OrderUrl, FinalizeUrl: string;
  Location: string;
  Attempts: Integer;
  Status: string;
  CertUrl: string;
  CsrDer: TBytes;
  CsrB64: string;

function SplitChain(const AllPem: string; out Leaf, Chain: string): Boolean;
const
  PemBegin = '-----BEGIN CERTIFICATE-----';
  PemEnd   = '-----END CERTIFICATE-----';
var
  Blocks: TArray<string>;
  StartPos, EndPos: Integer;
  S: string;
begin
  Result := False;
  Leaf := '';
  Chain := '';

  S := AllPem;
  SetLength(Blocks, 0);

  while True do
  begin
    StartPos := Pos(PemBegin, S);
    if StartPos = 0 then Break;

    EndPos := Pos(PemEnd, S);
    if EndPos = 0 then Break;

    EndPos := EndPos + Length(PemEnd);

    Blocks := Blocks + [Copy(S, StartPos, EndPos - StartPos)];

    Delete(S, 1, EndPos);
  end;

  if Length(Blocks) = 0 then
    Exit(False);

  Leaf := Blocks[0];

  if Length(Blocks) > 1 then
    Chain := String.Join(sLineBreak, Copy(Blocks, 1, Length(Blocks)-1))
  else
    Chain := '';

  Result := True;
end;

var
  AccountFile: string;
begin
  if Length(Domains) = 0 then
    raise EAcmeClientError.Create('No domains specified for certificate request');

  // Decide where to store account info (simple default path)
  if FAccountFile <> '' then
    AccountFile := FAccountFile
  else
    AccountFile := TPath.Combine(TPath.GetHomePath, 'acme-account.json');

  RegisterOrLoadAccount(Email, AccountFile);

  // 1) newOrder
  Payload := TJSONObject.Create;
  IdArr := TJSONArray.Create;
  try
    for I := 0 to High(Domains) do
    begin
      IdentObj := TJSONObject.Create;
      IdentObj.AddPair('type', 'dns');
      IdentObj.AddPair('value', Domains[I]);
      IdArr.AddElement(IdentObj);
    end;
    Payload.AddPair('identifiers', IdArr);

    Resp := JwsPost(FDirectory.NewOrderUrl, Payload, True, Location);
  finally
    FreeAndNil(Payload);
  end;

  OrderObj := Resp;
  try
    OrderUrl := Location;
    if OrderUrl = '' then
      // Some servers also include "location" or "url" in payload; try to read it
      if OrderObj.TryGetValue<string>('location', OrderUrl) then
      else if OrderObj.TryGetValue<string>('url', OrderUrl) then
        // ok
      else
        raise EAcmeClientError.Create('Order URL not found (Location header or url field)');

    FinalizeUrl := OrderObj.GetValue<string>('finalize');

    // 2) Solve authorizations
    ValidateAuthorizations(OrderObj, PrefType, OrderUrl);

    // 3) Generate CSR, finalize order
    FCertKey := TAcmeKeyPair.GenerateRsa2048;
    CsrDer := FCertKey.GenerateCsrDer(Domains);  // will raise until wired
    CsrB64 := Base64UrlEncode(CsrDer);

    Payload := TJSONObject.Create;
    try
      Payload.AddPair('csr', CsrB64);
      Resp := JwsPost(FinalizeUrl, Payload, True, Location);
    finally
      FreeAndNil(Payload);
      FreeAndNil(Resp);
    end;

    // 4) Poll order until valid and certificate URL present
    CertUrl := '';
    for Attempts := 1 to 30 do
    begin
      Sleep(2000);
      Resp := JwsPost(OrderUrl, nil, True, Location);
      try
        Status := Resp.GetValue<string>('status');
        if SameText(Status, 'valid') then
        begin
          CertUrl := Resp.GetValue<string>('certificate');
          Break;
        end;
      finally
        FreeAndNil(Resp);
      end;
    end;

    if CertUrl = '' then
      raise EAcmeClientError.Create('Order did not become valid or certificate URL not present');

    // 5) Download certificate chain
    var CompleteCertificatePem := DownloadCertPem(CertUrl);

    if not SplitChain(CompleteCertificatePem, CertificatePem, ChainPem) then
    begin
      // fallback – no splitting possible
      ChainPem := CertificatePem;
    end;

    PrivateKeyPem := FCertKey.ExportPrivateKeyPem;

    SaveCertificateSet(
        Domains,
        CertificatePem,
        ChainPem,
        PrivateKeyPem,
        FDirectoryUrl,
        IfThen(PrefType = ctDNS01, 'dns-01', 'http-01'),
        FDnsProviderName
        );

  finally
    FreeAndNil(OrderObj);
  end;
end;

procedure TAcmeClient.SaveCertificateSet(const Domains: TArray<string>;
  const CertPem, ChainPem, PrivateKeyPem: string;
  const DirectoryUrl, AuthMethod, DnsProvider: string);
var
  Name: string;
  Live, Archive, RenewalFile: string;
  Version: Integer;
  J: TJSONObject;
begin
  Name := Domains[0]; // Primary domain
  Live := GetLiveDir(Name);
  Archive := GetArchiveDir(Name);
  RenewalFile := GetRenewalFile(Name);

  EnsureDir(Live);
  EnsureDir(Archive);
  EnsureDir(TPath.GetDirectoryName(RenewalFile));

  // Choose next archive version
  Version := NextArchiveIndex(Name);

  // Write archive copies
  WritePemFile(TPath.Combine(Archive, Format('cert%d.pem', [Version])), CertPem);
  WritePemFile(TPath.Combine(Archive, Format('chain%d.pem', [Version])), ChainPem);
  WritePemFile(TPath.Combine(Archive, Format('fullchain%d.pem', [Version])),
    CertPem + sLineBreak + ChainPem);
  WritePemFile(TPath.Combine(Archive, Format('privkey%d.pem', [Version])), PrivateKeyPem);

  // Update "live" files
  UpdateLiveCertificate(Name, Version);

  // Write renewal metadata
  J := TJSONObject.Create;
  try
    var jsondomains := TJSONArray.Create;
    for var i := 0 to High(Domains) do
    begin
      jsondomains.Add(Domains[i]);
    end;
    J.AddPair('domains', jsondomains);
    J.AddPair('key_type', 'rsa2048');
    J.AddPair('created', DateToISO8601(Now, False));
    J.AddPair('last_renewed', DateToISO8601(Now, False));
    J.AddPair('directory', DirectoryUrl);
    J.AddPair('auth_method', AuthMethod);
    J.AddPair('dns_provider', DnsProvider);

    WritePemFile(RenewalFile, J.ToJSON);
  finally
    FreeAndNil(J);
  end;
end;


end.

