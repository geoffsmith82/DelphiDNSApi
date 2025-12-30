unit DNS.SPF.DnsWin32;

interface

uses
  Winapi.Windows,
  Winapi.WinSock,
  System.SysUtils,
  System.Generics.Collections,
  DNS.SPF.Types,
  Winapi.WinSock2  ;

type
  TSpfWinDnsResolver = class(TInterfacedObject, ISpfDnsResolver)
  private
    function StatusFromDns(Status: Integer): TDnsStatus;
  public
    function QueryTXT(const Name: string; out Txt: TArray<string>): TDnsStatus;
    function QueryA(const Name: string; out Addrs: TArray<string>): TDnsStatus;
    function QueryAAAA(const Name: string; out Addrs: TArray<string>): TDnsStatus;
    function QueryMX(const Name: string; out Hosts: TArray<string>): TDnsStatus;
  end;

implementation

const
  DNS_TYPE_TXT = $0010;
  DNS_TYPE_MX  = $000F;

  DNS_QUERY_STANDARD = $00000000;

  DNS_ERROR_RCODE_NAME_ERROR = 9003;
  DNS_ERROR_RCODE_NO_DATA    = 9001;

type

  PPWideCharArray = ^TPWideCharArray;
  TPWideCharArray = array[0..0] of PWideChar;

type
  IN6_ADDR = record
    Byte: array[0..15] of Byte;
  end;

type
  sockaddr_in6 = record
    sin6_family: Word;
    sin6_port: Word;
    sin6_flowinfo: Cardinal;
    sin6_addr: IN6_ADDR;
    sin6_scope_id: Cardinal;
  end;


 PSockAddrIn6 = ^sockaddr_in6;

  DNS_TXT_DATA = record
    dwStringCount: DWORD;
    pStringArray: PWideChar; // first element of inline array
  end;

  DNS_MX_DATA = record
    pNameExchange: PWideChar;
    wPreference: Word;
    Pad: Word; // alignment
  end;

  PDNS_RECORD = ^DNS_RECORD;
  DNS_RECORD = record
    pNext: PDNS_RECORD;
    pName: PWideChar;
    wType: Word;
    wDataLength: Word;
    Flags: DWORD;
    dwTtl: DWORD;
    dwReserved: DWORD;
    case Integer of
      0: (TXT: DNS_TXT_DATA);
      1: (MX: DNS_MX_DATA);
  end;

function DnsQuery_W(
  pszName: PWideChar;
  wType: Word;
  Options: DWORD;
  pExtra: Pointer;
  var ppQueryResults: PDNS_RECORD;
  pReserved: Pointer
): DWORD; stdcall; external 'dnsapi.dll';

procedure DnsRecordListFree(
  pRecordList: PDNS_RECORD;
  FreeType: Integer
); stdcall; external 'dnsapi.dll';

const
  DnsFreeRecordList = 1;


function TSpfWinDnsResolver.StatusFromDns(Status: Integer): TDnsStatus;
begin
  case Status of
    ERROR_SUCCESS: Result := dnsOk;
    DNS_ERROR_RCODE_NAME_ERROR: Result := dnsNxDomain;
    DNS_ERROR_RCODE_NO_DATA: Result := dnsNoData;
  else
    Result := dnsError;
  end;
end;

function TSpfWinDnsResolver.QueryTXT(const Name: string; out Txt: TArray<string>): TDnsStatus;
var
  Rec: PDNS_RECORD;
  R: PDNS_RECORD;
  Status: Integer;
  List: TList<string>;
  i : Integer;
  PStr: PPWideChar;
  S: PWideChar;
begin
  Txt := nil;
  List := TList<string>.Create;
  try
    Status := DnsQuery_W(
      PWideChar(Name),
      DNS_TYPE_TXT,
      DNS_QUERY_STANDARD,
      nil,
      Rec,
      nil
    );

    Result := StatusFromDns(Status);
    if Result <> dnsOk then Exit;

    R := Rec;
    while R <> nil do
    begin
      if R.wType = DNS_TYPE_TXT then
      begin
        if R.TXT.dwStringCount = 0 then
          Continue;

        // pStringArray points to the first PWSTR
        PStr := PPWideChar(@R.TXT.pStringArray);

        for I := 0 to Integer(R.TXT.dwStringCount) - 1 do
        begin
          S := PStr^;
          if S <> nil then
            List.Add(WideCharToString(S));

          Inc(PStr); // move to next PWSTR
        end;
      end;
      R := R.pNext;
    end;

    Txt := List.ToArray;
  finally
    if Rec <> nil then
      DnsRecordListFree(Rec, DnsFreeRecordList);
    FreeAndNil(List);
  end;
end;

function TSpfWinDnsResolver.QueryA(const Name: string; out Addrs: TArray<string>): TDnsStatus;
var
  Hints: addrinfoW;
  Res, P: PAddrInfoW;
  Addr: PSockAddrIn;
  B: PByte;
begin
  Addrs := nil;
  ZeroMemory(@Hints, SizeOf(Hints));
  Hints.ai_family := AF_INET;

  if GetAddrInfoW(PWideChar(Name), nil, Hints, Res) <> 0 then
    Exit(dnsNoData);

  try
    P := Res;
    while P <> nil do
    begin
      if P.ai_family = AF_INET then
      begin
        Addr := PSockAddrIn(P.ai_addr);
        B := @Addr.sin_addr;
        Addrs := Addrs + [
          Format('%d.%d.%d.%d', [B[0], B[1], B[2], B[3]])
        ];
      end;
      P := P.ai_next;
    end;
  finally
    FreeAddrInfoW(Res^);
  end;

  if Length(Addrs) > 0 then
    Result := dnsOk
  else
    Result := dnsNoData;
end;

function TSpfWinDnsResolver.QueryAAAA(const Name: string; out Addrs: TArray<string>): TDnsStatus;
var
  Hints: addrinfoW;
  Res, P: PAddrInfoW;
  BufLen: DWORD;
  Buf: array[0..45] of WideChar;
begin
  Addrs := nil;
  ZeroMemory(@Hints, SizeOf(Hints));
  Hints.ai_family := AF_INET6;

  if GetAddrInfoW(PWideChar(Name), nil, Hints, Res) <> 0 then
    Exit(dnsNoData);

  try
    P := Res;
    while P <> nil do
    begin
      if P.ai_family = AF_INET6 then
      begin
        BufLen := Length(Buf);
        if WSAAddressToStringW(
             P.ai_addr^,
             P.ai_addrlen,
             nil,
             Buf,
             BufLen
           ) = 0 then
        begin
          Addrs := Addrs + [WideCharToString(Buf)];
        end;
      end;
      P := P.ai_next;
    end;
  finally
    FreeAddrInfoW(Res^);
  end;

  if Length(Addrs) > 0 then
    Result := dnsOk
  else
    Result := dnsNoData;
end;



function TSpfWinDnsResolver.QueryMX(const Name: string; out Hosts: TArray<string>): TDnsStatus;
var
  Rec, R: PDNS_RECORD;
  Status: Integer;
  List: TList<string>;
begin
  Hosts := nil;
  List := TList<string>.Create;
  try
    Status := DnsQuery_W(
      PWideChar(Name),
      DNS_TYPE_MX,
      DNS_QUERY_STANDARD,
      nil,
      Rec,
      nil
    );

    Result := StatusFromDns(Status);
    if Result <> dnsOk then Exit;

    R := Rec;
    while R <> nil do
    begin
      if R.wType = DNS_TYPE_MX then
//        List.Add(WideCharToString(R.Data.MX.pNameExchange));
      R := R.pNext;
    end;

    Hosts := List.ToArray;
  finally
    if Rec <> nil then
      DnsRecordListFree(Rec, DnsFreeRecordList);
    FreeAndNil(List);
  end;
end;



end.
