claude-codex 監査レポート (ai-audit)
===

`make target=claude` / `make target=codex` で起動する `claude-codex` イメージに、
**エージェント (Claude Code / OpenAI Codex) の活動を監査するレポート機能** を入れています。
[issue #280](https://github.com/hinoshiba/dockerfiles/issues/280) の「audit系を追加する」
への対応です。

## なぜ auditd を中で動かさないのか (調査結果)

issue の元案は「`auditd` を結構強気で動かす」でしたが、**コンテナの中で `auditd` を
回すのは枯れた方式ではありません**。理由:

* Linux カーネルの audit subsystem は **namespace 化されていません**。
  コンテナ内の `auditd` は `CAP_AUDIT_CONTROL` / `CAP_AUDIT_READ` と、
  ホストと共有される audit netlink socket を要求します。
* そのため、非特権コンテナ (通常の `make target=claude` / `make target=codex` の起動) では
  そもそも起動に失敗するか、起動できてもホスト全体の audit イベントを巻き込みます。
  これは可搬性・安全性ともに不適切です。
* `auditd` を回すために `--privileged` 相当の権限を渡すのは、AI エージェントを
  閉じ込めるという本来の目的と真逆になります。

## 採用した枯れた方式: エージェント自身のセッションログを使う

特権を一切必要とせず、しかも **既に存在する** 高忠実度の監査証跡があります。
Claude Code と Codex は、エージェントが実行した **全コマンド** と **触れたファイル** を、
タイムスタンプ付きの行区切り JSON (JSONL) として永続化しています。

| エージェント | ログの場所 |
| --- | --- |
| OpenAI Codex | `~/.codex/sessions/**/*.jsonl` (既に `codex-monitor` が解析しているもの) |
| Claude Code | `~/.claude/projects/**/*.jsonl` |

これらは host からマウントされるため **コンテナを破棄しても残り**、
取得に権限が要らず、エージェントの実際の操作そのものを記録しています。
`ai-audit` はこのログを読み、

* ターミナル向けの **テキスト要約**、および
* 依存ゼロで自己完結した **HTML レポート** (issue の言う「グラフィカルにわかりやすい」)

を生成します。HTML は **JavaScript も CDN も使わず**、CSS だけで棒グラフ・タイムラインを
描くので、オフラインでそのまま開けて将来も壊れません。実装は Python 標準ライブラリのみで、
新たに入れるパッケージはありません。

## 使い方

```sh
ai-audit                  # テキスト要約 + HTML レポート (~/.ai-audit/ai-audit-report.html)
ai-audit --agent codex    # Codex のセッションのみ
ai-audit --agent claude   # Claude Code のセッションのみ
ai-audit --since 7d       # 直近 7 日 (30m / 24h / 7d / 2w …) のイベントのみ
ai-audit --top 30         # コマンド頻度チャートの上位件数
ai-audit --html report.html   # HTML の出力先を指定
ai-audit --text-only      # HTML を出さずテキスト要約だけ
ai-audit --json           # 機械可読な JSON 要約
ai-audit --help
```

引数なしの `ai-audit` は、テキスト要約を表示しつつ
`~/.ai-audit/ai-audit-report.html` に HTML レポートを書き出してパスを表示します。
ブラウザ等で開けるよう、HTML はカレントの作業ディレクトリ配下に出力してもよいでしょう
(`ai-audit --html ./audit.html`)。

### レポートの内容

* 概要カード: 総アクション数 / セッション数 / コマンド数 / ファイル書き込み・読み取り数
* エージェント別 (codex / claude) の内訳
* **コマンド頻度** (argv0 でまとめた棒グラフ)
* **アクティビティのタイムライン** (1時間単位のヒストグラム)
* セッション一覧 (アクション数・時間範囲)
* アクションログ (時刻・エージェント・種別・内容。直近 500 件まで)

## 設計上の性質

* **best-effort**: 壊れた行・想定外の行は読み飛ばし、活動が無ければ「無い」と表示して
  正常終了します。コンテナ起動を妨げません。
* **読み取り専用**: ログを解析するだけで、エージェントの挙動やコンテナ起動フローを
  変えません。自動では走らず、必要なときに手で実行します。
* **テレメトリ無し / 完全オフライン**: 外部送信は一切ありません。

> 補足: セッションログはエージェント自身が書くため、OS レベルの強制的な監査
> (例: 改ざん耐性のあるカーネル audit) ではありません。一方で「エージェントが
> 何をしたかを後から人間がレビューする」という目的には、特権不要で最も忠実かつ
> 枯れた情報源です。より強い OS レベル監査が必要なら、コンテナ内ではなく
> **ホスト側**で `auditd` を回す (コンテナのプロセスをホストから監査する) のが筋です。
