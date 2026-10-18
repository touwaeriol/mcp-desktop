import { useCallback, useEffect, useState } from "react";
import { Brush, Loader2, RefreshCw, X } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { call, desktop, message } from "@/lib/ipc";
import { t, useLanguage } from "@/lib/i18n";
import type { ReaCleaned, ReaSession, ReaSessions } from "@/lib/types";

const megabytes = (bytes: number) => Math.round(bytes / 1024 / 1024);

/**
 * REA processes launched by MCP clients on this machine. Ending one also ends
 * the analysis engines it started; cleanup ends trees whose client exited and
 * removes stale temporary folders.
 */
export function ReaSessionsCard() {
  useLanguage();
  const [list, setList] = useState<ReaSessions | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<number | null>(null);
  // Listing errors clear on the next successful refresh; action errors stay
  // until the next action.
  const [listError, setListError] = useState("");
  const [error, setError] = useState("");
  const load = useCallback(() => {
    call<ReaSessions>("list_rea_sessions")
      .then((next) => {
        setList(next);
        setListError("");
      })
      .catch((e) => setListError(message(e)));
  }, []);
  useEffect(() => {
    if (!desktop) return;
    load();
    const timer = window.setInterval(load, 5000);
    return () => window.clearInterval(timer);
  }, [load]);
  async function end(session: ReaSession) {
    setBusy(`end:${session.pid}`);
    setConfirming(null);
    setError("");
    try {
      setList(
        await call<ReaSessions>("end_rea_session", {
          pid: session.pid,
          startedAt: session.startedAt,
        }),
      );
      toast.success(
        session.client
          ? t("已结束 REA 进程；{0} 需要重新加载 MCP 才能再使用 REA", {
              0: session.client,
            })
          : t("已结束 REA 进程"),
      );
    } catch (e) {
      setError(message(e));
      load();
    } finally {
      setBusy(null);
    }
  }
  async function clean() {
    setBusy("clean");
    setError("");
    try {
      const result = await call<ReaCleaned>("clean_rea_sessions");
      toast.success(
        t("已结束 {0} 个残留 REA 进程，删除 {1} 个临时目录", {
          0: result.ended,
          1: result.removed,
        }),
      );
      if (result.failed.length)
        toast.warning(
          t("以下项目未能清理：{0}", { 0: result.failed.join("；") }),
          { duration: 10000 },
        );
    } catch (e) {
      setError(message(e));
    } finally {
      setBusy(null);
      load();
    }
  }
  const orphans = list?.sessions.filter((s) => s.orphan).length ?? 0;
  const leftovers = list?.leftovers ?? 0;
  return (
    <Card className="col-span-full" data-testid="rea-sessions">
      <CardHeader>
        <CardTitle>{t("REA 会话")}</CardTitle>
        <CardDescription className="leading-5">
          {t(
            "本机由客户端启动的 REA 进程。分析会话由客户端通过 open_binary / close_binary 管理；结束进程会同时结束它启动的 Ghidra 等分析引擎，对应客户端需重新加载 MCP。",
          )}
        </CardDescription>
        <CardAction className="toolbar">
          <Button
            variant="ghost"
            size="icon"
            aria-label={t("刷新")}
            disabled={!desktop || busy !== null}
            onClick={load}
          >
            <RefreshCw />
          </Button>
          <Button
            variant="outline"
            disabled={!desktop || busy !== null || orphans + leftovers === 0}
            title={t(
              "结束客户端已退出的 REA 进程，删除早于所有运行中会话的 rea-* 临时目录",
            )}
            onClick={() => void clean()}
          >
            {busy === "clean" ? (
              <Loader2 className="animate-spin" />
            ) : (
              <Brush />
            )}
            {t("清理残留（{0} 个进程、{1} 个临时目录）", {
              0: orphans,
              1: leftovers,
            })}
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent>
        {!list ? (
          <p className="text-sm text-muted-foreground">
            {desktop ? t("正在读取…") : t("桌面启动后可用")}
          </p>
        ) : list.sessions.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            {t("当前没有运行中的 REA 进程")}
          </p>
        ) : (
          <ul className="rea-sessions">
            {list.sessions.map((session) => (
              <li key={session.pid} data-testid={`rea-session-${session.pid}`}>
                <div className="min-w-0">
                  <strong>
                    {session.client ?? t("客户端已退出")}
                    {session.orphan && (
                      <Badge variant="outline" className="ml-2">
                        {t("残留")}
                      </Badge>
                    )}
                  </strong>
                  <small className="mono">
                    {t("PID {0} · 启动于 {1} · {2} 个进程 · {3} MB", {
                      0: session.pid,
                      1: new Date(session.startedAt * 1000).toLocaleString(),
                      2: session.processes,
                      3: megabytes(session.memory),
                    })}
                  </small>
                </div>
                {confirming === session.pid ? (
                  <div className="toolbar">
                    <Button
                      variant="destructive"
                      size="sm"
                      disabled={busy !== null}
                      onClick={() => void end(session)}
                    >
                      {t("确认结束")}
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setConfirming(null)}
                    >
                      {t("取消")}
                    </Button>
                  </div>
                ) : (
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={!desktop || busy !== null}
                    onClick={() => setConfirming(session.pid)}
                  >
                    {busy === `end:${session.pid}` ? (
                      <Loader2 className="animate-spin" />
                    ) : (
                      <X />
                    )}
                    {t("结束")}
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
        {(error || listError) && (
          <p role="alert" className="mt-3 text-destructive text-sm break-all">
            {error || listError}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
