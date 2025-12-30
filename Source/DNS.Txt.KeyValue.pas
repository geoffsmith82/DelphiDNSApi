unit DNS.Txt.KeyValue;

interface

uses
  System.SysUtils,
  System.Generics.Collections;

type
  TTxtKvPair = record
    Key: string;
    Value: string;
    Raw: string;
  public
    class function Create(const AKey, AValue, ARaw: string): TTxtKvPair; static;
  end;

  TTxtKvPairs = TArray<TTxtKvPair>;

  TTxtKvIssueKind = (
    kvEmptySegment,
    kvMissingEquals,
    kvEmptyKey,
    kvDuplicateKey
  );

  TTxtKvIssue = record
    Kind: TTxtKvIssueKind;
    Segment: string;
  public
    class function Create(AKind: TTxtKvIssueKind; const ASegment: string): TTxtKvIssue; static;
  end;

  TTxtKvIssues = TArray<TTxtKvIssue>;

  function ParseTxtKeyValueList(const Txt: string; out Pairs: TTxtKvPairs; out Issues: TTxtKvIssues): Boolean;

implementation

class function TTxtKvIssue.Create(AKind: TTxtKvIssueKind; const ASegment: string): TTxtKvIssue;
begin
  Result.Kind := AKind;
  Result.Segment := ASegment;
end;

class function TTxtKvPair.Create(const AKey, AValue, ARaw: string): TTxtKvPair;
begin
  Result.Key := AKey;
  Result.Value := AValue;
  Result.Raw := ARaw;
end;


function ParseTxtKeyValueList(const Txt: string; out Pairs: TTxtKvPairs; out Issues: TTxtKvIssues): Boolean;
var
  Segments: TArray<string>;
  PairList: TList<TTxtKvPair>;
  IssueList: TList<TTxtKvIssue>;
  SeenKeys: TDictionary<string, Integer>;
  Seg, Key, Val, Raw: string;
  EqPos: Integer;
begin
  PairList := TList<TTxtKvPair>.Create;
  IssueList := TList<TTxtKvIssue>.Create;
  SeenKeys := TDictionary<string, Integer>.Create;
  try
    Segments := Txt.Split([';']);

    for Seg in Segments do
    begin
      Raw := Trim(Seg);

      if Raw = '' then
      begin
        IssueList.Add(TTxtKvIssue.Create(kvEmptySegment, Seg));
        Continue;
      end;

      EqPos := Pos('=', Raw);
      if EqPos = 0 then
      begin
        IssueList.Add(TTxtKvIssue.Create(kvMissingEquals, Raw));
        Continue;
      end;

      Key := LowerCase(Trim(Copy(Raw, 1, EqPos - 1)));
      Val := Trim(Copy(Raw, EqPos + 1, MaxInt));

      if Key = '' then
      begin
        IssueList.Add(TTxtKvIssue.Create(kvEmptyKey, Raw));
        Continue;
      end;

      if SeenKeys.ContainsKey(Key) then
        IssueList.Add(TTxtKvIssue.Create(kvDuplicateKey, Key))
      else
        SeenKeys.Add(Key, 1);

      PairList.Add(TTxtKvPair.Create(Key, Val, Raw));
    end;

    Pairs := PairList.ToArray;
    Issues := IssueList.ToArray;
    Result := Length(Pairs) > 0;
  finally
    FreeAndNil(PairList);
    FreeAndNil(IssueList);
    FreeAndNil(SeenKeys);
  end;
end;

end.
