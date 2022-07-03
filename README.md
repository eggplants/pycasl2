# PyCASL3 & PyCOMET3(CASLII Assembler & Simulater)

## インストール

```bash
pip install git+https://github.com/eggplants/pycasl3
```

## 使い方

```shellsession
$ pycasl3 test/data.cas  # casl2 binary file
$ pycomet3 test/data.com # comet2 binary file
```

---

## 概要

PyCASL3, PyCOMET3 は[CASLII](http://www.ipa.go.jp/english/humandev/data/Term_LangSpec.pdf)のアセンブラ及びシュミレータです。

このプログラムは、

- [PyCASL2&PyComet2](http://www.image.med.osaka-u.ac.jp/member/nakamoto/pycasl2/index.html)
- [mitaki28/pycasl2](https://github.com/mitaki28/pycasl2)

を改良して作られています。

基本的な仕様については、[PyCASL2&PyComet2のドキュメント](http://www.image.med.osaka-u.ac.jp/member/nakamoto/pycasl2/index.html)を参照してください。

## 変更点 (PyCASL2&PyComet2->mitaki28/pycasl2)

現段階で変更が施されている部分は、シュミレータのPyComet2のみです。

- コマンド入力の際に、ヒストリ補完やカーソルキーによる移動が可能になっています。
- コマンド入力の際に、不正な引数を与えると強制終了するバグを修正しています。
- コードを全体的にリファクタリングしています。
- ファイルを複数のモジュールに分割し、メンテナンス性を高めています。

## 変更点 (mitaki28/pycasl2->eggplants/pycasl3)

- Python3対応

## TODO

- テストをほとんど行なっていないためバグが発生する可能性が高いです

## ライセンス

このプログラムはGPL2ライセンスに従います。[LICENSE](LICENSE)をご覧ください。
