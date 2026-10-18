// Browser IPC regression for the REA sessions card; process discovery, tree
// termination and temporary folder cleanup are verified by Rust tests.
const { chromium } = require(
  process.env.PLAYWRIGHT_MODULE_PATH || "playwright",
);
const assert = require("node:assert/strict");
(async () => {
  const browser = await chromium.launch({
    channel: process.env.PLAYWRIGHT_CHANNEL || "chromium",
    headless: true,
  });
  const errors = [];
  try {
    for (const language of ["zh-CN", "en"]) {
      const zh = language === "zh-CN";
      const context = await browser.newContext({
        locale: language,
        viewport: { width: 1180, height: 820 },
      });
      const page = await context.newPage();
      page.on("pageerror", (error) => errors.push(error.message));
      await page.addInitScript((language) => {
        window.isTauri = true;
        let sequence = 0;
        const project = {
          id: "fixture",
          name: "Fixture",
          rootPath: "D:\\fixture",
          canonicalPath: "D:\\fixture",
          previousRoots: [],
          notes: "",
          autoStart: false,
          createdAt: "2026-10-17",
          updatedAt: "2026-10-17",
        };
        const mib = 1024 * 1024;
        const test = (window.__rea = {
          calls: [],
          endError: null,
          sessions: [
            {
              pid: 100,
              client: "Codex",
              clientPid: 10,
              startedAt: 1792200000,
              memory: 380 * mib,
              processes: 5,
              orphan: false,
            },
            {
              pid: 200,
              client: null,
              clientPid: null,
              startedAt: 1792100000,
              memory: 120 * mib,
              processes: 3,
              orphan: true,
            },
          ],
          leftovers: 2,
        });
        const list = () => ({
          sessions: test.sessions.map((s) => ({ ...s })),
          leftovers: test.leftovers,
        });
        window.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener() {} };
        window.__TAURI_INTERNALS__ = {
          transformCallback() {
            return ++sequence;
          },
          unregisterCallback() {},
          async invoke(command, args = {}) {
            test.calls.push({ command, args });
            if (command.startsWith("plugin:event|")) return ++sequence;
            if (command === "list_rea_sessions") return list();
            if (command === "end_rea_session") {
              if (test.endError) throw test.endError;
              test.sessions = test.sessions.filter(
                (s) => !(s.pid === args.pid && s.startedAt === args.startedAt),
              );
              return list();
            }
            if (command === "clean_rea_sessions") {
              const ended = test.sessions.filter((s) => s.orphan).length;
              test.sessions = test.sessions.filter((s) => !s.orphan);
              test.leftovers = 0;
              return {
                ended,
                removed: 1,
                failed: ["C:\\Temp\\rea-ghidra-1: LOCKED_FIXTURE"],
              };
            }
            if (
              ["list_serena_snapshots", "list_warpgrep_snapshots"].includes(
                command,
              )
            )
              return {};
            if (command === "list_projects") return [project];
            if (command === "detect_codegraph")
              return {
                available: true,
                entry: "D:\codegraph.cmd",
                version: "1.6.2",
                error: null,
              };
            if (command === "get_project_snapshot")
              return {
                projectId: project.id,
                generation: "fixture",
                sequence: ++sequence,
                state: "stopped",
                sessions: 0,
                indexState: "ready",
                error: null,
              };
            if (command === "get_client_config_status")
              return ["codex", "claude", "cursor", "devin"].map((client) => ({
                client,
                state: "missing",
                path: `.${client}/mcp.json`,
                message: null,
              }));
            if (
              [
                "read_logs",
                "get_project_tasks",
                "list_config_backups",
              ].includes(command)
            )
              return [];
            if (command === "get_update_snapshot")
              return {
                sequence: 0,
                status: "idle",
                currentVersion: "0.1.30",
                latestVersion: null,
                notes: null,
                checkedAt: null,
                autoCheck: false,
                canInstall: true,
                downloaded: 0,
                total: null,
                error: null,
              };
            if (command === "get_settings")
              return {
                language,
                codegraphEntry: null,
                serenaEntry: null,
                indexConcurrency: 2,
                closeBehavior: "tray",
                activeClient: "codex",
                appDataDir: "D:\\fixture-data",
              };
            throw Error(`Unexpected command ${command}`);
          },
        };
      }, language);
      await page.goto(process.env.UI_TEST_URL || "http://127.0.0.1:1420");
      await page.getByText("Fixture", { exact: true }).first().click();
      await page
        .getByTestId("engine-row-rea")
        .locator("button")
        .first()
        .click();
      const card = page.getByTestId("rea-sessions");
      const codex = card.getByTestId("rea-session-100");
      const orphan = card.getByTestId("rea-session-200");
      await codex.waitFor();
      assert.match(await codex.innerText(), /Codex/);
      assert.match(
        await codex.innerText(),
        zh
          ? /PID 100 · .* · 5 个进程 · 380 MB/
          : /PID 100 · .* · 5 processes · 380 MB/,
      );
      assert.match(
        await orphan.innerText(),
        zh ? /客户端已退出\s*残留/ : /Client exited\s*Leftover/,
      );
      const clean = card.getByRole("button", {
        name: zh
          ? "清理残留（1 个进程、2 个临时目录）"
          : "Clean up (1 processes, 2 temporary folders)",
      });
      assert.equal(await clean.isDisabled(), false);

      // Ending asks for confirmation first, and cancelling ends nothing.
      const end = (row) =>
        row.getByRole("button", { name: zh ? "结束" : "End", exact: true });
      const confirm = (row) =>
        row.getByRole("button", { name: zh ? "确认结束" : "Confirm end" });
      await end(codex).click();
      await codex.getByRole("button", { name: zh ? "取消" : "Cancel" }).click();
      await end(codex).waitFor();
      const ended = () =>
        page.evaluate(() =>
          window.__rea.calls
            .filter((call) => call.command === "end_rea_session")
            .map((call) => call.args),
        );
      assert.deepEqual(await ended(), []);

      await page.evaluate(
        () =>
          (window.__rea.endError = {
            code: "SESSION_NOT_FOUND",
            message: "GONE_FIXTURE",
          }),
      );
      await end(codex).click();
      await confirm(codex).click();
      await card.getByText("GONE_FIXTURE", { exact: true }).waitFor();
      await page.evaluate(() => (window.__rea.endError = null));
      await end(codex).click();
      await confirm(codex).click();
      await page
        .getByText(
          zh
            ? "已结束 REA 进程；Codex 需要重新加载 MCP 才能再使用 REA"
            : "REA process ended; reload MCP in Codex to use REA again",
        )
        .waitFor();
      await codex.waitFor({ state: "detached" });
      assert.deepEqual((await ended()).at(-1), {
        pid: 100,
        startedAt: 1792200000,
      });

      await clean.click();
      await page
        .getByText(
          zh
            ? "已结束 1 个残留 REA 进程，删除 1 个临时目录"
            : "Ended 1 leftover REA processes and deleted 1 temporary folders",
        )
        .waitFor();
      await page.getByText(/LOCKED_FIXTURE/).waitFor();
      await card
        .getByText(
          zh ? "当前没有运行中的 REA 进程" : "No REA processes are running",
        )
        .waitFor();
      await card
        .getByRole("button", {
          name: zh
            ? "清理残留（0 个进程、0 个临时目录）"
            : "Clean up (0 processes, 0 temporary folders)",
        })
        .and(page.locator(":disabled"))
        .waitFor();
      await card.scrollIntoViewIfNeeded();
      await page.screenshot({
        path: `.tools/rea-sessions-${language}.png`,
        fullPage: false,
      });
      await context.close();
    }
    assert.deepEqual(errors, []);
    console.log("REA sessions UI checks passed.");
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
