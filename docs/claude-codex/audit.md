claude-codex 監査 (exec auditing + ai-audit レポート)
===

`make target=claude` / `make target=codex` で起動する `claude-codex` イメージに、
**エージェント (Claude Code / OpenAI Codex) が行った作業を OS レベルで記録し、
グラフィカルなレポートにする** 仕組みを入れています。
[issue #280](https://github.com/hinoshiba/dockerfiles/issues/280) への対応です。

構成は2層です。

1. **取得層 (snoopy)** — コンテナ内で実行された全コマンド (`execve`) を記録する。
2. **レポート層 (`ai-audit`)** — 取得したログ + エージェントのセッションログを集計し、
   テキスト要約と HTML レポートを出力する。

## 調査: コンテナ内で「真の syscall 監査」はできない

issue の元案は「`auditd` を結構強気で動かす」でした。しかし**非特権コンテナの中で
カーネルレベルの syscall 監査を回すのは原理的にできません**。

- `auditd`（カーネル audit）/ `eBPF`(Falco・execsnoop 等) / プロセスアカウンティング
  (`accton`) は、いずれもカーネルのサブシステムが **namespace 化されておらず**、
  `CAP_AUDIT_CONTROL` / `CAP_BPF` / `CAP_SYS_PACCT`（実質 `--privileged`）を要求します。
- 通常の `make target=claude` / `make target=codex`（エージェントを閉じ込めるための
  非特権サンドボックス）では `EPERM` で起動できないか、できてもホスト全体を巻き込みます。
- 監査のためにサンドボックスの特権を上げるのは本末転倒です。

→ 真の syscall レベルが要るなら、コンテナ内ではなく**ホスト側**で `auditd`/`Falco` を
コンテナの cgroup に絞って回すのが筋です（後述「限界」）。その手前で、**特権なし・
コンテナ内で完結・枯れている**現実解が snoopy です。

## 採用した枯れた方式: snoopy による exec 監査

[snoopy](https://github.com/a2o/snoopy) は約20年の実績がある `LD_PRELOAD` 型の
コマンドロガーです。`/etc/ld.so.preload` でイメージ全体に有効化され、コンテナ内で
起きた **全 `execve()`** を、エージェントの自己申告とは独立に記録します。特権は不要で、
syslog デーモンが無いコンテナでも**ファイルに直接**書けます。

記録されるのは「実際に実行されたコマンド」です。1 行 1 exec で、`ai-audit` が
パースできるパイプ区切り形式 ([`snoopy.ini`](../../dockerfiles/claude-codex/snoopy.ini)):

```
snoopy-audit|<unix時刻>|<uid>|<ユーザ名>|<cwd>|<コマンドライン>
```

コマンドラインは最後に置いてあるので、中に `|` が含まれても安全にパースできます。

### ログの場所と永続化

- コンテナ内のパス: `/var/log/ai-audit/exec.log`
- `make target=claude/codex` で起動すると、Makefile がホストの
  `~/.shared_cache.ai-audit` をここに bind mount します。コンテナは `--rm` で
  破棄されますが、**ログはホスト側に残ります**（`~/.shared_cache.ai-audit/exec.log`）。

### 無効化

```sh
EXEC_AUDIT=0 make target=claude   # このコンテナ起動だけ snoopy を無効化
```

(エントリポイントが `/etc/ld.so.preload` を空にして無効化します。)

## レポート層: ai-audit

[`ai-audit`](../../dockerfiles/claude-codex/ai-audit.py)（Python 標準ライブラリのみ、
新規パッケージなし）は、snoopy の exec ログと、エージェントが永続化している
セッションログを **統合** して集計します。

| ソース | 場所 | 性質 |
| --- | --- | --- |
| exec (snoopy) | `/var/log/ai-audit/exec.log` | OS レベル・エージェント非依存の実行記録 |
| Codex | `~/.codex/sessions/**/*.jsonl` | どのエージェントか・ファイル編集等の構造化情報 (`codex-monitor` も利用) |
| Claude Code | `~/.claude/projects/**/*.jsonl` | 同上 |

snoopy が「独立した実行の地の文」を、セッションログが「構造 (エージェント種別・
ファイル操作・セッション単位)」を補い合います。

```sh
ai-audit                  # テキスト要約 + HTML (~/.ai-audit/ai-audit-report.html)
ai-audit --agent exec     # snoopy の exec ログだけ
ai-audit --agent codex    # Codex のセッションだけ
ai-audit --since 7d       # 直近 7 日 (30m/24h/7d/2w)
ai-audit --exec-log PATH  # exec ログのパスを指定 (既定: /var/log/ai-audit/exec.log)
ai-audit --html ./a.html  # HTML 出力先を指定
ai-audit --json           # 機械可読サマリ
ai-audit --help
```

HTML レポート (JavaScript も CDN も使わず CSS だけで描画。オフラインで開ける) の内容:

- 概要カード: 総アクション数 / セッション数 / コマンド数 / ファイル書き込み・読み取り数
- ソース別 (exec / codex / claude) の内訳
- **コマンド頻度** (argv0 でまとめた棒グラフ)
- **アクティビティのタイムライン** (1時間単位のヒストグラム)
- セッション一覧、アクションログ (直近 500 件)

## ビルド時セルフテスト (なぜ必要か)

CI は `claude-codex` を **ビルドのみ** で検証し、実行スモークはスキップします。
そのため `/etc/ld.so.preload` 経由の snoopy が実際に動くか・ログ形式が `ai-audit` で
パースできるかは、放っておくと CI で検出できません。

これを潰すため、[Dockerfile](../../dockerfiles/claude-codex/Dockerfile) のビルド内に
セルフテストを埋め込んでいます。snoopy を有効化した直後に既知のコマンドを実行し、
(1) exec ログにその行が記録されること、(2) 行が想定フォーマットであること、
(3) `ai-audit` がそれを exec イベントとして集計できること、を確認し、いずれか
壊れていればビルドを失敗させます。**CI ビルドが通ること = end-to-end で動くこと**に
なります。

## 限界

- **exec 単位であって全 syscall ではありません。** ファイル read/write やネットワーク
  といった個々の syscall までは追いません（それは特権が要るカーネル audit の領域）。
  「何のコマンドを実行したか」は完全に取れます。
- `LD_PRELOAD` 方式なので、静的リンクのバイナリや、`LD_PRELOAD` を意図的に外した
  プロセスは捕捉できません。悪意ある回避には強くありません。
- **改ざん耐性のある本物の syscall 監査が必要なら**、コンテナ内ではなく**ホスト側**で
  `auditd` / `Falco` を当該コンテナの cgroup / PID namespace に絞って回してください。
  これがこの種の監査の本来の置き場所です。
