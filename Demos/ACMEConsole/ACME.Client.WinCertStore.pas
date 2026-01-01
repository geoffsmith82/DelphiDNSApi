unit ACME.Client.WinCertStore;

interface

{$IFDEF MSWINDOWS}



type
  TWindowsCertStoreLocation = (wslCurrentUser, wslLocalMachine);

function InstallCertificatePemToWindowsStore(
  const CertPem, PrivateKeyPem: string;
  const StoreName: string = 'WebHosting';
  StoreLocation: TWindowsCertStoreLocation = wslLocalMachine;
  const PfxPassword: string = '';
  ExportableKey: Boolean = True;
  const FriendlyName: string = ''
): string;

{$ELSE}

type
  TWindowsCertStoreLocation = (wslCurrentUser, wslLocalMachine);

function InstallCertificatePemToWindowsStore(
  const CertPem, PrivateKeyPem: string;
  const StoreName: string = 'WebHosting';
  StoreLocation: TWindowsCertStoreLocation = wslLocalMachine;
  const PfxPassword: string = '';
  ExportableKey: Boolean = True;
  const FriendlyName: string = ''
): string;

{$ENDIF}

implementation

{$IFDEF MSWINDOWS}

uses
  System.SysUtils,
  System.Classes,
  Winapi.Windows,
  ACME.TaurusCrypto,
  TaurusTLS,
  IdCTypes,
  TaurusTLSHeaders_bio,
  TaurusTLSHeaders_pkcs12,
  TaurusTLSHeaders_pem,
  TaurusTLSHeaders_x509,
  TaurusTLSHeaders_evp;

function IsUserAnAdmin: BOOL; stdcall; external 'shell32.dll';

// OpenSSL types (pointers)
type
  PX509 = Pointer;
  PBIO = Pointer;
  PEVP_PKEY = Pointer;
  PEVP_PKEY_CTX = Pointer;
  PBIGNUM = Pointer;
  PRSA = Pointer;
  PPX509 = ^PX509;
  PPEVP_PKEY = ^PEVP_PKEY;
  PPByte = ^PByte;

// EC types
type
  PEC_KEY = Pointer;
  PEC_GROUP = Pointer;
  PEC_POINT = Pointer;

// PKCS12
type
  PPKCS12 = Pointer;


  HCERTSTORE = Pointer;
  PCCERT_CONTEXT = Pointer;

  PCRYPT_DATA_BLOB = ^CRYPT_DATA_BLOB;
  CRYPT_DATA_BLOB = record
    cbData: DWORD;
    pbData: PByte;
  end;

const
  CERT_SHA1_HASH_PROP_ID = 3;
  CERT_FRIENDLY_NAME_PROP_ID = 11;

  X509_ASN_ENCODING = $00000001;
  PKCS_7_ASN_ENCODING = $00010000;

  CRYPT_EXPORTABLE = $00000001;
  CRYPT_USER_KEYSET = $00001000;
  CRYPT_MACHINE_KEYSET = $00002000;

  CERT_STORE_OPEN_EXISTING_FLAG = $00004000;
  CERT_SYSTEM_STORE_CURRENT_USER = $00010000;
  CERT_SYSTEM_STORE_LOCAL_MACHINE = $00020000;

  CERT_STORE_ADD_REPLACE_EXISTING = 3;

  CERT_FIND_SHA1_HASH = $00010000;

  // Provider ID used by CertOpenStore
  CERT_STORE_PROV_SYSTEM: PAnsiChar = PAnsiChar(Pointer(10));

function PFXImportCertStore(pPFX: PCRYPT_DATA_BLOB; szPassword: PWideChar; dwFlags: DWORD): HCERTSTORE; stdcall; external 'crypt32.dll';
function CertOpenStore(lpszStoreProvider: PAnsiChar; dwMsgAndCertEncodingType: DWORD; hCryptProv: THandle; dwFlags: DWORD; pvPara: Pointer): HCERTSTORE; stdcall; external 'crypt32.dll';
function CertEnumCertificatesInStore(hCertStore: HCERTSTORE; pPrevCertContext: PCCERT_CONTEXT): PCCERT_CONTEXT; stdcall; external 'crypt32.dll';
function CertAddCertificateContextToStore(hCertStore: HCERTSTORE; pCertContext: PCCERT_CONTEXT; dwAddDisposition: DWORD; ppStoreContext: Pointer): BOOL; stdcall; external 'crypt32.dll';
function CertCloseStore(hCertStore: HCERTSTORE; dwFlags: DWORD): BOOL; stdcall; external 'crypt32.dll';
function CertGetCertificateContextProperty(pCertContext: PCCERT_CONTEXT; dwPropId: DWORD; pvData: Pointer; var pcbData: DWORD): BOOL; stdcall; external 'crypt32.dll';
function CertFindCertificateInStore(hCertStore: HCERTSTORE; dwCertEncodingType: DWORD; dwFindFlags: DWORD; dwFindType: DWORD; pvFindPara: Pointer; pPrevCertContext: PCCERT_CONTEXT): PCCERT_CONTEXT; stdcall; external 'crypt32.dll';
function CertSetCertificateContextProperty(pCertContext: PCCERT_CONTEXT; dwPropId: DWORD; dwFlags: DWORD; pvData: Pointer): BOOL; stdcall; external 'crypt32.dll';
function CertFreeCertificateContext(pCertContext: PCCERT_CONTEXT): BOOL; stdcall; external 'crypt32.dll';


function BytesToHex(const Bytes: TBytes): string;
const
  Hex: array[0..15] of Char = ('0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f');
var
  I: Integer;
begin
  SetLength(Result, Length(Bytes) * 2);
  for I := 0 to High(Bytes) do
  begin
    Result[I * 2 + 1] := Hex[Bytes[I] shr 4];
    Result[I * 2 + 2] := Hex[Bytes[I] and $0F];
  end;
end;

function HexToBytes(const Hex: string): TBytes;
var
  I: Integer;
  CleanHex: string;
begin
  CleanHex := LowerCase(Hex).Replace(' ', '').Replace(':', '');
  if (Length(CleanHex) mod 2) <> 0 then
    raise Exception.Create('Invalid hex string length');

  SetLength(Result, Length(CleanHex) div 2);
  for I := 0 to High(Result) do
  begin
    Result[I] := StrToInt('$' + CleanHex.Substring(I * 2, 2));
  end;
end;

function LoadX509FromPem(const Pem: string): PX509;
var
  Bio: PBIO;
  pemLen: TIdC_INT;
  AnsiPem: AnsiString;

begin
  AnsiPem := AnsiString(Pem);
  pemLen := Length(Pem);
  Bio := BIO_new_mem_buf(AnsiPem[1], pemLen);
  if Bio = nil then
    raise Exception.Create('BIO_new_mem_buf failed for certificate');
  try
    Result := PEM_read_bio_X509(Bio, nil, nil, nil);
    if Result = nil then
      raise Exception.Create('PEM_read_bio_X509 failed');
  finally
    BIO_free(Bio);
  end;

  if Result <> nil then
    Exit;


  if Result = nil then
    raise Exception.Create('Failed to load certificate as PEM or DER');
end;

function BuildPkcs12(const CertPem, PrivateKeyPem, PfxPassword: string): TBytes;
var
  Cert: PX509;
  Key: TAcmeKeyPair;
  P12: PPKCS12;
  Len: Integer;
  P: PByte;
  PassAnsi: AnsiString;
  FriendlyNameAnsi: AnsiString;
begin
  Cert := LoadX509FromPem(CertPem);
  try
    Key := TAcmeKeyPair.LoadKeyFromPem(PrivateKeyPem);
    try
      var PassPtr: PAnsiChar;
      if PfxPassword = '' then
        PassPtr := nil
      else
        PassPtr := PAnsiChar(AnsiString(PfxPassword));

      FriendlyNameAnsi := AnsiString('acmeconsole');

      // Use OpenSSL defaults for algorithms/iters by passing zeros.
      P12 := PKCS12_create(
        PassPtr,
        PAnsiChar(FriendlyNameAnsi),
        PEVP_PKEY(Key.RawKey),
        Cert,
        nil,
        0, 0, 0, 0, 0
      );

      if P12 = nil then
        raise Exception.Create('PKCS12_create failed');

      try
        Len := i2d_PKCS12(P12, nil);
        if Len <= 0 then
          raise Exception.Create('i2d_PKCS12 failed (size)');

        SetLength(Result, Len);
        if Len > 0 then
        begin
          P := @Result[0];
          if i2d_PKCS12(P12, @P) <> Len then
            raise Exception.Create('i2d_PKCS12 failed (encode)');
        end;
      finally
        PKCS12_free(P12);
      end;

    finally
      FreeAndNil(Key);
    end;
  finally
    X509_free(Cert);
  end;
end;

function TryGetCertThumbprintSha1(const CertCtx: PCCERT_CONTEXT; out Thumbprint: string): Boolean;
var
  Hash: array[0..19] of Byte;
  HashLen: DWORD;
  Bytes: TBytes;
begin
  Thumbprint := '';
  HashLen := SizeOf(Hash);

  Result := CertGetCertificateContextProperty(CertCtx, CERT_SHA1_HASH_PROP_ID, @Hash[0], HashLen);
  if not Result then
    Exit;

  SetLength(Bytes, HashLen);
  Move(Hash[0], Bytes[0], HashLen);
  Thumbprint := BytesToHex(Bytes);
end;

function InstallCertificatePemToWindowsStore(
  const CertPem, PrivateKeyPem: string;
  const StoreName: string;
  StoreLocation: TWindowsCertStoreLocation;
  const PfxPassword: string;
  ExportableKey: Boolean;
  const FriendlyName: string
): string;
var
  PfxBytes: TBytes;
  Blob: CRYPT_DATA_BLOB;
  Flags: DWORD;
  ImportStore: HCERTSTORE;
  TargetStore: HCERTSTORE;
  StoreFlags: DWORD;
  CertCtx: PCCERT_CONTEXT;
  AddedAny: Boolean;
  Thumb: string;
begin
  if (StoreLocation = wslLocalMachine) and not IsUserAnAdmin then
    raise Exception.Create('Installing certificates into the Local Machine store requires administrator privileges. Please run as administrator or use --windows-store-location currentuser.');

  PfxBytes := BuildPkcs12(CertPem, PrivateKeyPem, PfxPassword);

  if Length(PfxBytes) = 0 then
    raise Exception.Create('Generated PFX was empty');

  Blob.cbData := Length(PfxBytes);
  Blob.pbData := @PfxBytes[0];

  Flags := 0;
  case StoreLocation of
    wslCurrentUser: Flags := Flags or CRYPT_USER_KEYSET;
    wslLocalMachine: Flags := Flags or CRYPT_MACHINE_KEYSET;
  end;

  if ExportableKey then
    Flags := Flags or CRYPT_EXPORTABLE;

  var PasswordPtr: PWideChar;
  if PfxPassword = '' then
    PasswordPtr := nil
  else
    PasswordPtr := PWideChar(PfxPassword);

  ImportStore := PFXImportCertStore(@Blob, PasswordPtr, Flags);
  if ImportStore = nil then
    raise Exception.CreateFmt('PFXImportCertStore failed (%d)', [GetLastError]);

  try
    StoreFlags := CERT_STORE_OPEN_EXISTING_FLAG;
    case StoreLocation of
      wslCurrentUser: StoreFlags := StoreFlags or CERT_SYSTEM_STORE_CURRENT_USER;
      wslLocalMachine: StoreFlags := StoreFlags or CERT_SYSTEM_STORE_LOCAL_MACHINE;
    end;

    TargetStore := CertOpenStore(
      CERT_STORE_PROV_SYSTEM,
      0,
      0,
      StoreFlags,
      PChar(StoreName)
    );

    if TargetStore = nil then
      raise Exception.CreateFmt('CertOpenStore failed (%d)', [GetLastError]);

    try
      AddedAny := False;
      Result := '';

      CertCtx := nil;
      while True do
      begin
        CertCtx := CertEnumCertificatesInStore(ImportStore, CertCtx);
        if CertCtx = nil then
          Break;

        if not AddedAny then
        begin
          if TryGetCertThumbprintSha1(CertCtx, Thumb) then
            Result := Thumb;
        end;

        if not CertAddCertificateContextToStore(TargetStore, CertCtx, CERT_STORE_ADD_REPLACE_EXISTING, nil) then
          raise Exception.CreateFmt('CertAddCertificateContextToStore failed (%d)', [GetLastError]);

        AddedAny := True;
      end;

      if not AddedAny then
        raise Exception.Create('No certificates were imported from PFX');

      // Set friendly name if provided
      if FriendlyName <> '' then
      begin
        var ThumbBytes: TBytes := HexToBytes(Thumb);
        if Length(ThumbBytes) = 20 then
        begin
          var FoundCert: PCCERT_CONTEXT := CertFindCertificateInStore(
            TargetStore, X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, 0,
            CERT_FIND_SHA1_HASH, @ThumbBytes[0], nil
          );
          if FoundCert <> nil then
          begin
            var WideName: WideString := FriendlyName;
            CertSetCertificateContextProperty(FoundCert, CERT_FRIENDLY_NAME_PROP_ID, 0, PWideChar(WideName));
            CertFreeCertificateContext(FoundCert);
          end;
        end;
      end;

    finally
      CertCloseStore(TargetStore, 0);
    end;
  finally
    CertCloseStore(ImportStore, 0);
  end;
end;

{$ELSE}

uses
  System.SysUtils;

function InstallCertificatePemToWindowsStore(
  const CertPem, PrivateKeyPem: string;
  const StoreName: string;
  StoreLocation: TWindowsCertStoreLocation;
  const PfxPassword: string;
  ExportableKey: Boolean;
  const FriendlyName: string
): string;
begin
  raise Exception.Create('Windows certificate store import is only supported on Windows.');
end;

{$ENDIF}

end.
