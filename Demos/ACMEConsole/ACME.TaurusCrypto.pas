unit ACME.TaurusCrypto;

interface

uses
  System.SysUtils,
  System.Classes,
  System.JSON,
  System.Hash,
  System.NetEncoding,
  TaurusTLS,
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_rsa,
  TaurusTLSHeaders_bio,
  TaurusTLSHeaders_pem,
  TaurusTLSHeaders_x509,
  TaurusTLSHeaders_asn1,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_x509v3,
  TaurusTLSHeaders_obj_mac,
  TaurusTLSHeaders_bn,
  IdCTypes
  ;

type
  EAcmeCryptoError = class(Exception);

  TAcmeKeyType = (akRsa2048, akEcP256);

  // Wraps an OpenSSL key (EVP_PKEY *)
  TAcmeKeyPair = class
  private
    FKey: Pointer; // PEVP_PKEY
    FKeyType: TAcmeKeyType;
    procedure CheckKey;

  public
    constructor Create(AKey: Pointer; AKeyType: TAcmeKeyType);
    destructor Destroy; override;


    class function LoadKeyFromPem(const Pem: string): TAcmeKeyPair;
    class function GenerateRsa2048: TAcmeKeyPair;
    class function GenerateEcP256: TAcmeKeyPair;

    function ExportPrivateKeyPem: string;
    function ExportPublicKeyPem: string;

    function BuildJwk: TJSONObject;
    function ComputeJwkThumbprint: string;

    // RS256 / ES256 JWS signature (result is base64url of signature)
    function SignJws(const ProtectedB64, PayloadB64: string): string;

    // CSR with SANs (DNS:domain1, DNS:domain2, ...)
    function GenerateCsrPem(const Domains: TArray<string>): string;
    // wrapper: PEM → DER bytes
    function GenerateCsrDer(const Domains: TArray<string>): TBytes;

    property KeyType: TAcmeKeyType read FKeyType;
    property RawKey: Pointer read FKey; // PEVP_PKEY
  end;

function Base64UrlEncode(const Bytes: TBytes): string;
function Base64UrlEncodeStr(const S: string): string;

implementation

// === Shared helpers ===

function Base64UrlEncode(const Bytes: TBytes): string;
begin
  Result := TNetEncoding.Base64url.EncodeBytesToString(Bytes);
end;

function Base64UrlEncodeStr(const S: string): string;
begin
  Result := Base64UrlEncode(TEncoding.UTF8.GetBytes(S));
end;

function BN_num_bytes(a: PBIGNUM): Integer;
begin
  Result := (BN_num_bits(a) + 7) div 8;
end;

function BnToBase64Url(ABn: PBIGNUM): string;
var
  Len: Integer;
  Bytes: TBytes;
begin
  if ABn = nil then
    raise EAcmeCryptoError.Create('BnToBase64Url: BIGNUM is nil');

  Len := BN_num_bytes(ABn);
  if Len <= 0 then
    raise EAcmeCryptoError.Create('BnToBase64Url: BN_num_bytes failed');

  SetLength(Bytes, Len);
  if Len > 0 then
  begin
    // BN_bn2bin writes big-endian, minimal length bytes
    if BN_bn2bin(ABn, PByte(Bytes)) <> Len then
      raise EAcmeCryptoError.Create('BnToBase64Url: BN_bn2bin failed');
  end;

  Result := Base64UrlEncode(Bytes);
end;


// === TAcmeKeyPair ===

constructor TAcmeKeyPair.Create(AKey: Pointer; AKeyType: TAcmeKeyType);
begin
  inherited Create;
  FKey := AKey;
  FKeyType := AKeyType;
end;

destructor TAcmeKeyPair.Destroy;
begin
  if FKey <> nil then
  begin
    // Properly free the EVP_PKEY
    EVP_PKEY_free(PEVP_PKEY(FKey));
    FKey := nil;
  end;
  inherited;
end;

procedure TAcmeKeyPair.CheckKey;
begin
  if FKey = nil then
    raise EAcmeCryptoError.Create('Key not initialised');
end;

class function TAcmeKeyPair.GenerateRsa2048: TAcmeKeyPair;
var
  Ctx: PEVP_PKEY_CTX;
  PKey: PEVP_PKEY;
  Err: Integer;
begin
  Ctx := EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nil);
  if Ctx = nil then
    raise EAcmeCryptoError.Create('EVP_PKEY_CTX_new_id failed');

  try
    Err := EVP_PKEY_keygen_init(Ctx);
    if Err <= 0 then
      raise EAcmeCryptoError.Create('EVP_PKEY_keygen_init failed');

    // Set RSA key size to 2048 bits
    Err := RSA_pkey_ctx_ctrl(ctx, EVP_PKEY_OP_KEYGEN,EVP_PKEY_CTRL_RSA_KEYGEN_BITS, 2048, nil);
    if Err <= 0 then
      raise EAcmeCryptoError.Create('EVP_PKEY_CTX_set_rsa_keygen_bits failed');

    PKey := nil;
    Err := EVP_PKEY_keygen(Ctx, @PKey);
    if (Err <= 0) or (PKey = nil) then
      raise EAcmeCryptoError.Create('EVP_PKEY_keygen failed');

    Result := TAcmeKeyPair.Create(PKey, akRsa2048);
  finally
    EVP_PKEY_CTX_free(Ctx);
  end;
end;

class function TAcmeKeyPair.GenerateEcP256: TAcmeKeyPair;
var
  Key: Pointer; // EVP_PKEY*
begin
  // TODO:
  //   - Use EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nil)
  //   - Set curve NID_X9_62_prime256v1
  //   - EVP_PKEY_keygen(...)
  Key := nil;
  raise EAcmeCryptoError.Create('GenerateEcP256 not wired to OpenSSL yet');

  Result := TAcmeKeyPair.Create(Key, akEcP256);
end;

function TAcmeKeyPair.ExportPrivateKeyPem: string;
var
  Bio: PBIO;
  Buf: array[0..4095] of AnsiChar;
  Len: Integer;
  Temp: TBytes;
begin
  CheckKey;

  Bio := BIO_new(BIO_s_mem());
  if Bio = nil then
    raise EAcmeCryptoError.Create('BIO_new failed');

  try
    if PEM_write_bio_PrivateKey(Bio, PEVP_PKEY(FKey), nil, nil, 0, nil, nil) <= 0 then
      raise EAcmeCryptoError.Create('PEM_write_bio_PrivateKey failed');

    // Read all from BIO
    Result := '';
    repeat
      Len := BIO_read(Bio, Buf, SizeOf(Buf));  // ← FIXED
      if Len > 0 then
      begin
        SetLength(Temp, Len);
        Move(Buf[0], Temp[0], Len);
        Result := Result + TEncoding.ASCII.GetString(Temp);
      end;
    until Len <= 0;
  finally
    BIO_free(Bio);
  end;
end;

function TAcmeKeyPair.ExportPublicKeyPem: string;
var
  Bio: PBIO;
  Buf: array[0..4095] of AnsiChar;
  Len: Integer;
  Temp: TBytes;
begin
  CheckKey;

  Bio := BIO_new(BIO_s_mem());
  if Bio = nil then
    raise EAcmeCryptoError.Create('BIO_new failed');

  try
    if PEM_write_bio_PUBKEY(Bio, PEVP_PKEY(FKey)) <= 0 then
      raise EAcmeCryptoError.Create('PEM_write_bio_PUBKEY failed');

    Result := '';
    repeat
      Len := BIO_read(Bio, Buf, SizeOf(Buf));
      if Len > 0 then
      begin
        SetLength(Temp, Len);
        Move(Buf[0], Temp[0], Len);
        Result := Result + TEncoding.ASCII.GetString(Temp);
      end;
    until Len <= 0;
  finally
    BIO_free(Bio);
  end;
end;

function TAcmeKeyPair.BuildJwk: TJSONObject;
var
  Rsa: PRSA;
  Nbn, Ebn: PBIGNUM;
  NStr, EStr: string;
begin
  CheckKey;
  Result := TJSONObject.Create;

  case FKeyType of
    akRsa2048:
    begin
      Rsa := EVP_PKEY_get1_RSA(PEVP_PKEY(FKey));
      if Rsa = nil then
        raise EAcmeCryptoError.Create('EVP_PKEY_get1_RSA failed');

      try
        // Extract BIGNUM pointers
        RSA_get0_key(Rsa, @Nbn, @Ebn, nil);

        if Nbn = nil then
          raise EAcmeCryptoError.Create('RSA_get0_key: modulus (n) is nil');
        if Ebn = nil then
          raise EAcmeCryptoError.Create('RSA_get0_key: exponent (e) is nil');

        NStr := BnToBase64Url(Nbn);
        EStr := BnToBase64Url(Ebn);

        Result.AddPair('kty', 'RSA');
        Result.AddPair('n', NStr);
        Result.AddPair('e', EStr);
      finally
        // decrements refcount on RSA structure
        RSA_free(Rsa);
      end;
    end;

    akEcP256:
      raise EAcmeCryptoError.Create('BuildJwk for EC not implemented yet');
  end;
end;

function TAcmeKeyPair.ComputeJwkThumbprint: string;
var
  Jwk: TJSONObject;
  CanonObj: TJSONObject;
  Canon: string;
  HashBytes: TBytes;
begin
  Jwk := BuildJwk;
  CanonObj := TJSONObject.Create;
  try
    // RFC 7638 requires lexicographically ordered keys
    // We must manually insert keys **in canonical order**
    case FKeyType of
      akRsa2048:
        begin
          // RSA canonical order:  e, kty, n
          CanonObj.AddPair('e',  Jwk.GetValue('e').Clone as TJSONValue);
          CanonObj.AddPair('kty', TJSONString.Create('RSA'));
          CanonObj.AddPair('n',  Jwk.GetValue('n').Clone as TJSONValue);
        end;

      akEcP256:
        begin
          // EC canonical order:  crv, kty, x, y
          CanonObj.AddPair('crv', TJSONString.Create('P-256'));
          CanonObj.AddPair('kty', TJSONString.Create('EC'));
          CanonObj.AddPair('x',   Jwk.GetValue('x').Clone as TJSONValue);
          CanonObj.AddPair('y',   Jwk.GetValue('y').Clone as TJSONValue);
        end;
    end;

    // Convert to canonical JSON string
    Canon := CanonObj.ToJSON;

    // Hash JSON and Base64-URL encode
    HashBytes := THashSHA2.GetHashBytes(Canon);
    Result := Base64UrlEncode(HashBytes);

  finally
    FreeAndNil(CanonObj);
    FreeAndNil(Jwk);
  end;
end;



class function TAcmeKeyPair.LoadKeyFromPem(const Pem: string): TAcmeKeyPair;
var
  Bio: PBIO;
  PKey: PEVP_PKEY;
  pemLen: TIdC_INT;
  AnsiPem: AnsiString;
begin
  // Convert to AnsiString explicitly (BIO expects raw bytes)
  AnsiPem := AnsiString(Pem);
  pemLen := Length(AnsiPem);

  Bio := BIO_new_mem_buf(AnsiPem[1], pemLen);

  if Bio = nil then
    raise EAcmeCryptoError.Create('BIO_new_mem_buf failed');

  try
    PKey := PEM_read_bio_PrivateKey(Bio, nil, nil, nil);
    if PKey = nil then
      raise EAcmeCryptoError.Create('PEM_read_bio_PrivateKey failed');

    Result := TAcmeKeyPair.Create(PKey, akRsa2048); // RSA only for now
  finally
    BIO_free(Bio);
  end;
end;


function TAcmeKeyPair.SignJws(const ProtectedB64, PayloadB64: string): string;
var
  ToSign: UTF8String;
  Ctx: PEVP_MD_CTX;
  Md: PEVP_MD;
  SigLen: TIdC_SIZET;
  SigBytes: TBytes;
begin
  CheckKey;

  if FKeyType <> akRsa2048 then
    raise EAcmeCryptoError.Create('SignJws: only RSA (RS256) is implemented');

  // Data to sign: ASCII/UTF-8 of "protected.payload"
  ToSign := UTF8String(ProtectedB64 + '.' + PayloadB64);

  Ctx := EVP_MD_CTX_new();
  if Ctx = nil then
    raise EAcmeCryptoError.Create('EVP_MD_CTX_new failed');

  try
    Md := EVP_sha256;
    if Md = nil then
      raise EAcmeCryptoError.Create('EVP_sha256 returned nil');

    // Initialize context for RSASSA-PKCS1-v1_5 with SHA-256
    if EVP_DigestSignInit(Ctx, nil, Md, nil, PEVP_PKEY(FKey)) <> 1 then
      raise EAcmeCryptoError.Create('EVP_DigestSignInit failed');

    if (Length(ToSign) > 0) and
       (EVP_DigestUpdate(Ctx, @ToSign[1], Length(ToSign)) <> 1) then
      raise EAcmeCryptoError.Create('EVP_DigestSignUpdate failed');

    // First call with nil to get required length
    SigLen := 0;
    if EVP_DigestSignFinal(Ctx, nil, @SigLen) <> 1 then
      raise EAcmeCryptoError.Create('EVP_DigestSignFinal (size query) failed');

    if SigLen = 0 then
      raise EAcmeCryptoError.Create('EVP_DigestSignFinal returned zero-length signature');

    SetLength(SigBytes, SigLen);

    // Second call to actually write the signature
    if EVP_DigestSignFinal(Ctx, @SigBytes[0], @SigLen) <> 1 then
      raise EAcmeCryptoError.Create('EVP_DigestSignFinal (sign) failed');

    // In case OpenSSL wrote fewer bytes than reserved
    if SigLen <> NativeUInt(Length(SigBytes)) then
      SetLength(SigBytes, SigLen);

    Result := Base64UrlEncode(SigBytes);
  finally
    EVP_MD_CTX_free(Ctx);
  end;
end;


function TAcmeKeyPair.GenerateCsrPem(const Domains: TArray<string>): string;
var
  Req: PX509_REQ;
  Name: PX509_NAME;
  Bio: PBIO;
  Buf: array[0..4095] of AnsiChar;
  Len: Integer;
  Temp: TBytes;
  I: Integer;
  // CN as UTF-8
  CNBytes: TBytes;
  // SAN bits
  SanStr: AnsiString;
  Ext: PX509_EXTENSION;
  Exts: Pointer; // typically PSTACK_OF_X509_EXTENSION = Pointer in Taurus headers
begin
  CheckKey;

  if Length(Domains) = 0 then
    raise EAcmeCryptoError.Create('GenerateCsrPem: no domains supplied');

  Req := X509_REQ_new();
  if Req = nil then
    raise EAcmeCryptoError.Create('X509_REQ_new failed');
  try
    // ---- Subject CN (UTF-8) ----
    Name := X509_NAME_new();
    if Name = nil then
      raise EAcmeCryptoError.Create('X509_NAME_new failed');
    try
      CNBytes := TEncoding.UTF8.GetBytes(Domains[0]);

      if X509_NAME_add_entry_by_txt(
            Name,
            'CN',
            MBSTRING_UTF8,          // we are passing UTF-8 bytes
            PByte(CNBytes),
            Length(CNBytes),
            -1,
            0
         ) <> 1 then
        raise EAcmeCryptoError.Create('X509_NAME_add_entry_by_txt failed');

      if X509_REQ_set_subject_name(Req, Name) <> 1 then
        raise EAcmeCryptoError.Create('X509_REQ_set_subject_name failed');
    finally
      X509_NAME_free(Name);
    end;

    // ---- Public key ----
    if X509_REQ_set_pubkey(Req, PEVP_PKEY(FKey)) <> 1 then
      raise EAcmeCryptoError.Create('X509_REQ_set_pubkey failed');

    // ---- SAN extension: "DNS:dom1,DNS:dom2,..."
    SanStr := '';
    for I := 0 to High(Domains) do
    begin
      if I > 0 then
        SanStr := SanStr + ',';
      // SAN DNS names are IA5String; domains should be ASCII/punycode
      SanStr := SanStr + 'DNS:' + AnsiString(Domains[I]);
    end;

    // Build subjectAltName extension using X509v3 helper
    Ext := X509V3_EXT_conf_nid(
             nil,        // no CONF
             nil,        // no ctx
             NID_subject_alt_name,
             PAnsiChar(SanStr)
           );
    if Ext = nil then
      raise EAcmeCryptoError.Create('X509V3_EXT_conf_nid for subjectAltName failed');

    // Create a stack of extensions and add our SAN
    Exts := sk_X509_EXTENSION_new_null;
    if Exts = nil then
    begin
      X509_EXTENSION_free(Ext);
      raise EAcmeCryptoError.Create('sk_X509_EXTENSION_new_null failed');
    end;

    try
      if sk_X509_EXTENSION_push(Exts, Ext) = 0 then
        raise EAcmeCryptoError.Create('sk_X509_EXTENSION_push failed');

      if X509_REQ_add_extensions(Req, Exts) <> 1 then
        raise EAcmeCryptoError.Create('X509_REQ_add_extensions failed');
    finally
      // frees stack AND contained extensions
      sk_X509_EXTENSION_pop_free(Exts, @X509_EXTENSION_free);
    end;

    // ---- Sign CSR (SHA-256) ----
    if X509_REQ_sign(Req, PEVP_PKEY(FKey), EVP_sha256()) <= 0 then
      raise EAcmeCryptoError.Create('X509_REQ_sign failed');

    // ---- Write CSR to PEM memory BIO ----
    Bio := BIO_new(BIO_s_mem());
    if Bio = nil then
      raise EAcmeCryptoError.Create('BIO_new failed');
    try
      if PEM_write_bio_X509_REQ(Bio, Req) <> 1 then
        raise EAcmeCryptoError.Create('PEM_write_bio_X509_REQ failed');

      Result := '';
      repeat
        Len := BIO_read(Bio, Buf, SizeOf(Buf));
        if Len > 0 then
        begin
          SetLength(Temp, Len);
          Move(Buf[0], Temp[0], Len);
          Result := Result + TEncoding.ASCII.GetString(Temp);
        end;
      until Len <= 0;
    finally
      BIO_free(Bio);
    end;
  finally
    X509_REQ_free(Req);
  end;
end;




function TAcmeKeyPair.GenerateCsrDer(const Domains: TArray<string>): TBytes;
var
  Pem, Base64Body: string;
  Lines: TArray<string>;
  Line: string;
begin
  // This assumes GenerateCsrPem returns standard PEM CSR:
  // -----BEGIN CERTIFICATE REQUEST-----
  // base64...
  // -----END CERTIFICATE REQUEST-----

  Pem := GenerateCsrPem(Domains);

  // Strip header/footer and whitespace to get plain base64
  Base64Body := '';
  Lines := Pem.Replace(#13, '').Split([#10]);
  for Line in Lines do
  begin
    if (Line = '') then
      Continue;
    if Line.StartsWith('-----') then
      Continue;
    Base64Body := Base64Body + Line.Trim;
  end;

  // Decode base64 → DER bytes
  Result := TNetEncoding.Base64.DecodeStringToBytes(Base64Body);
end;

initialization
  LoadOpenSSLLibrary;

finalization
  UnLoadOpenSSLLibrary;
end.

